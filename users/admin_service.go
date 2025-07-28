package users

import (
	"github.com/gin-gonic/gin"

	"github.com/spdeepak/go-jwt-server/api"
)

type adminService struct {
	storage Storage
}

type AdminService interface {
	GetListOfUsers(ctx *gin.Context, params api.GetListOfUsersParams) ([]api.UserDetails, error)
}

func NewAdminService(storage Storage) AdminService {
	return &adminService{
		storage: storage,
	}
}

func (a *adminService) GetListOfUsers(ctx *gin.Context, params api.GetListOfUsersParams) ([]api.UserDetails, error) {

}
