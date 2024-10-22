package auth

import (
	ssov1 "github.com/GolangLessons/protos/gen/go/sso"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	emptyValue = 0
)

func validateLogin(req *ssov1.LoginRequest) error {
	err := validation.Validate(req.GetEmail(), validation.Required, validation.NilOrNotEmpty, is.Email,
		validation.Length(5, 20))
	if err != nil {
		return err
	}

	err = validation.Validate(req.GetPassword(), validation.Required, validation.NilOrNotEmpty,
		validation.Length(5, 20))
	if err != nil {
		return err
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app id is required")
	}
	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	err := validation.Validate(req.GetEmail(), validation.Required, validation.NilOrNotEmpty, is.Email,
		validation.Length(5, 20))
	if err != nil {
		return err
	}

	err = validation.Validate(req.GetPassword(), validation.Required, validation.NilOrNotEmpty,
		validation.Length(5, 20))
	if err != nil {
		return err
	}
	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.UserId == emptyValue {
		return status.Error(codes.InvalidArgument, "app id is required")
	}
	return nil
}
