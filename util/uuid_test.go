package util

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
)

func TestUUIDToPgtypeUUID_OK(t *testing.T) {
	id := "1de01ae3-b51d-4173-892a-69ab5e4eeb5a"
	uid := uuid.MustParse(id)
	pguid := UUIDToPgtypeUUID(uid)
	assert.True(t, pguid.Valid)
	assert.Equal(t, id, pguid.String())
}

func TestUUIDToPgtypeUUID_NOK(t *testing.T) {
	pguid := UUIDToPgtypeUUID(uuid.UUID{})
	assert.False(t, pguid.Valid)
}

func TestPgtypeUUIDToUUID_OK(t *testing.T) {
	id := "1de01ae3-b51d-4173-892a-69ab5e4eeb5a"
	u := uuid.MustParse(id)
	uid, err := PgtypeUUIDToUUID(pgtype.UUID{
		Bytes: u,
		Valid: true,
	})
	assert.NoError(t, err)
	assert.Equal(t, id, uid.String())
}

func TestPgtypeUUIDToUUID_NOK(t *testing.T) {
	uid, err := PgtypeUUIDToUUID(pgtype.UUID{
		Valid: false,
	})
	assert.NoError(t, err)
	assert.Equal(t, uuid.Nil, uid)
}
