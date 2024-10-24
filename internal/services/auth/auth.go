package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	authjwt "sso/internal/lib/jwt"
	"sso/internal/storage"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppId       = errors.New("invalid app id")
	ErrUserAlreadyExists  = errors.New("user already exists")
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

// New returns new instance of the Auth service
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:          log,
		userProvider: userProvider,
		userSaver:    userSaver,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
		slog.String("appID", fmt.Sprint(appID)))

	log.Info("attempting to login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", err.Error())

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)

		}

		a.log.Error("filed to get user", err.Error())
		return "", fmt.Errorf("%s: %w", op, err)
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid password", err.Error())
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	var app models.App
	app, err = a.appProvider.App(ctx, appID)

	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged successfully")

	var token string
	token, err = authjwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", err.Error())
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return token, nil
}

func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email))

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Error("failed to hash password", err.Error())
		return 0, fmt.Errorf("%s, %w", op, err)
	}

	var id int64
	id, err = a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Info("user already exists")
			return 0, fmt.Errorf("%s: %w", op, ErrUserAlreadyExists)
		}
		log.Error("failed to save user", err.Error())
		return 0, fmt.Errorf("%s, %w", op, err)
	}

	log.Info("successfully saved user")
	return id, nil
}

func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (bool, error) {
	const op = "auth.IsAdmin"
	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID))

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userID)

	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Info("user not found")

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppId)
		}
		log.Error("failed to check if user is admin", err.Error())
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checking if user is admin")
	return isAdmin, nil
}
