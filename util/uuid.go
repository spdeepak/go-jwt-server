package util

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func PgtypeUUIDToUUID(p pgtype.UUID) (uuid.UUID, error) {
	if !p.Valid {
		return uuid.Nil, nil
	}
	return uuid.FromBytes(p.Bytes[:])
}

func UUIDToPgtypeUUID(u uuid.UUID) pgtype.UUID {
	if u == uuid.Nil {
		return pgtype.UUID{Valid: false}
	}

	return pgtype.UUID{
		Bytes: u,
		Valid: true,
	}
}
