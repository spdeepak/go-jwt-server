package tokens

type userAgent struct {
}

type UserAgent interface {
}

func NewUserAgent() UserAgent {
	return &userAgent{}
}
