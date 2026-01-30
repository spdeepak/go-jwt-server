package twoFA

type User2FASetup struct {
	Secret  string `json:"secret"`
	QrImage string `json:"qr_image"`
	Url     string `json:"url"`
}
