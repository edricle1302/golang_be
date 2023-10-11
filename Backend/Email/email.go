package email

import (
	"io/ioutil"
	"log"
	"net/smtp"
	"strings"
	"text/template"
)

func GenerateHTML(templatePath string, data interface{}) (string, error) {
	// Read the HTML template file
	templateBytes, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return "", err
	}

	// Get file name from template path
	templateFileName := templatePath[strings.LastIndex(templatePath, "/")+1:]

	// Parse the template
	tmpl, err := template.New(templateFileName).Parse(string(templateBytes))
	if err != nil {
		return "", err
	}

	// Create a buffer to hold the generated HTML
	htmlBuffer := new(strings.Builder)

	// Execute the template with the provided data
	err = tmpl.Execute(htmlBuffer, data)
	if err != nil {
		return "", err
	}

	// Return the generated HTML string
	return htmlBuffer.String(), nil
}

func SendEmail(toEmail string, subject string, templateFile string, data interface{}) error {
	// Set up authentication information.
	auth := smtp.PlainAuth("", "fogi.noreply@gmail.com", "phnouzgpzyhhfwfm", "smtp.gmail.com")

	forgot_email, err := GenerateHTML(templateFile, data)
	if err != nil {
		return err
	}

	// Set up the email message.
	to := []string{toEmail}
	msg := []byte("To: " + to[0] + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		forgot_email + "\r\n")

	// Connect to the SMTP server and send the email message.
	err = smtp.SendMail("smtp.gmail.com:587", auth, "fogi.noreply@gmail.com", to, msg)
	if err != nil {
		log.Println(err)
		log.Println("Error sending activation code ", err)
		return err
	}
	log.Println("Activation code sent successfully")
	return nil
}
