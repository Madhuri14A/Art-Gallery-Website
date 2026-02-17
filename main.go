package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var sessions = make(map[string]string)

type Painting struct {
	ID          int
	Title       string
	Artist      string
	Price       int
	Description string
	ImagePath   string
}

// User represents a user in the system
type User struct {
	ID        int
	Name      string
	Email     string
	CreatedAt string
}

// PageData holds data passed to templates
type PageData struct {
	LoggedIn  bool
	UserName  string
	Error     string
	Success   string
	Email     string
	Name      string
	Paintings []Painting
	Users     []User
}

// generateSessionToken creates a secure random session token
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// getSessionCookie retrieves the session cookie from the request
func getSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// getUserFromSession checks if user is logged in and returns username
func getUserFromSession(r *http.Request) (string, bool) {
	sessionToken := getSessionCookie(r)
	if sessionToken == "" {
		return "", false
	}
	email, exists := sessions[sessionToken]
	if !exists {
		return "", false
	}

	// Get user name from database
	var name string
	err := db.QueryRow("SELECT name FROM users WHERE email = ?", email).Scan(&name)
	if err != nil {
		return "", false
	}
	return name, true
}

// homeHandler handles the home page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	userName, loggedIn := getUserFromSession(r)

	data := PageData{
		LoggedIn: loggedIn,
		UserName: userName,
	}

	tmpl, err := template.ParseFiles("template/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

// loginHandler handles user login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Check if already logged in
		if _, loggedIn := getUserFromSession(r); loggedIn {
			http.Redirect(w, r, "/paintings", http.StatusSeeOther)
			return
		}

		tmpl, _ := template.ParseFiles("template/login.html")
		tmpl.Execute(w, PageData{})
	} else if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var dbPassword string
		var name string

		// Look for the user in the database
		err := db.QueryRow("SELECT name, password FROM users WHERE email = ?", email).Scan(&name, &dbPassword)
		if err != nil {
			tmpl, _ := template.ParseFiles("template/login.html")
			tmpl.Execute(w, PageData{
				Error: "Invalid email or password",
				Email: email,
			})
			return
		}

		// Verify password
		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			tmpl, _ := template.ParseFiles("template/login.html")
			tmpl.Execute(w, PageData{
				Error: "Invalid email or password",
				Email: email,
			})
			return
		}

		// Create session
		sessionToken, err := generateSessionToken()
		if err != nil {
			http.Error(w, "Could not create session", http.StatusInternalServerError)
			return
		}

		sessions[sessionToken] = email

		// Set cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Path:     "/",
			MaxAge:   3600 * 24, // 24 hours
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		fmt.Printf("User %s logged in successfully!\n", name)
		http.Redirect(w, r, "/paintings", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	if sessionToken != "" {
		delete(sessions, sessionToken)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	fmt.Println("User logged out.")
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

// registerHandler handles user registration
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Check if already logged in
		if _, loggedIn := getUserFromSession(r); loggedIn {
			http.Redirect(w, r, "/paintings", http.StatusSeeOther)
			return
		}

		tmpl, err := template.ParseFiles("template/register.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, PageData{})
	} else if r.Method == "POST" {
		name := r.FormValue("name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Validate password length
		if len(password) < 6 {
			tmpl, _ := template.ParseFiles("template/register.html")
			tmpl.Execute(w, PageData{
				Error: "Password must be at least 6 characters long",
				Name:  name,
				Email: email,
			})
			return
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Could not process password", http.StatusInternalServerError)
			return
		}

		// Insert into the database
		_, err = db.Exec("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", name, email, string(hashedPassword))
		if err != nil {
			tmpl, _ := template.ParseFiles("template/register.html")
			tmpl.Execute(w, PageData{
				Error: "Email already exists or registration failed",
				Name:  name,
				Email: email,
			})
			return
		}

		// Create session automatically after registration
		sessionToken, err := generateSessionToken()
		if err != nil {
			http.Error(w, "Could not create session", http.StatusInternalServerError)
			return
		}

		sessions[sessionToken] = email

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Path:     "/",
			MaxAge:   3600 * 24,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		fmt.Printf("User %s registered successfully!\n", name)
		http.Redirect(w, r, "/paintings", http.StatusSeeOther)
	}
}

// paintingsHandler displays all paintings from the database
func paintingsHandler(w http.ResponseWriter, r *http.Request) {
	userName, loggedIn := getUserFromSession(r)

	// Fetch paintings from database
	rows, err := db.Query("SELECT id, title, artist, price, description, COALESCE(image_path, '') FROM paintings ORDER BY id")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var paintings []Painting
	for rows.Next() {
		var p Painting
		err := rows.Scan(&p.ID, &p.Title, &p.Artist, &p.Price, &p.Description, &p.ImagePath)
		if err != nil {
			log.Println("Error scanning painting:", err)
			continue
		}
		paintings = append(paintings, p)
	}

	data := PageData{
		LoggedIn:  loggedIn,
		UserName:  userName,
		Paintings: paintings,
	}

	tmpl, err := template.ParseFiles("template/paintings.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

// initDatabase sets up the database and creates tables
func initDatabase() error {
	var err error
	db, err = sql.Open("sqlite3", "./gallery.db")
	if err != nil {
		return err
	}

	// Create users table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	// Create paintings table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS paintings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		artist TEXT NOT NULL,
		price INTEGER NOT NULL,
		description TEXT,
		image_path TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	// Insert sample paintings if table is empty
	var count int
	db.QueryRow("SELECT COUNT(*) FROM paintings").Scan(&count)
	if count == 0 {
		samplePaintings := []Painting{
			{Title: "Sunset Over the Ocean", Artist: "ABC", Price: 5000, Description: "A breathtaking view of the sun setting over calm waters", ImagePath: "sunset.jpg"},
			{Title: "Forest in Spring", Artist: "BCD", Price: 3500, Description: "Lush greenery and blooming flowers in a serene forest", ImagePath: "forest.jpg"},
			{Title: "Abstract Dreams", Artist: "Madhuri", Price: 4200, Description: "Bold colors and dynamic shapes in modern abstraction", ImagePath: "abstract.jpg"},
			{Title: "Tranquil Seascape", Artist: "Jaya", Price: 4000, Description: "Peaceful waves lapping against a sandy shore", ImagePath: "seascape.jpg"},
			{Title: "Mountain Majesty", Artist: "ABC", Price: 5500, Description: "Snow-capped peaks reaching toward the sky", ImagePath: "mountain.jpg"},
			{Title: "Urban Nights", Artist: "BCD", Price: 3800, Description: "City lights illuminating the evening skyline", ImagePath: "urban.jpg"},
		}

		for _, p := range samplePaintings {
			_, err = db.Exec("INSERT INTO paintings (title, artist, price, description, image_path) VALUES (?, ?, ?, ?, ?)",
				p.Title, p.Artist, p.Price, p.Description, p.ImagePath)
			if err != nil {
				log.Println("Error inserting sample painting:", err)
			}
		}
		fmt.Println("Sample paintings added to database")
	}

	return nil
}

// sessionCleanup removes expired sessions periodically
func sessionCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			// In a real app, you'd track session expiration times
			// For now, this is a placeholder
			fmt.Println("Session cleanup running...")
		}
	}()
}

// adminHandler displays the admin panel
func adminHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	userName, loggedIn := getUserFromSession(r)
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Fetch all paintings
	rows, err := db.Query("SELECT id, title, artist, price, description, COALESCE(image_path, '') FROM paintings ORDER BY id")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var paintings []Painting
	for rows.Next() {
		var p Painting
		rows.Scan(&p.ID, &p.Title, &p.Artist, &p.Price, &p.Description, &p.ImagePath)
		paintings = append(paintings, p)
	}

	// Fetch all users
	userRows, err := db.Query("SELECT id, name, email, created_at FROM users ORDER BY id")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer userRows.Close()

	var users []User
	for userRows.Next() {
		var u User
		userRows.Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt)
		users = append(users, u)
	}

	data := PageData{
		LoggedIn:  loggedIn,
		UserName:  userName,
		Paintings: paintings,
		Users:     users,
	}

	// Check for success/error messages from query params
	if r.URL.Query().Get("success") == "added" {
		data.Success = "Painting added successfully!"
	} else if r.URL.Query().Get("success") == "deleted" {
		data.Success = "Painting deleted successfully!"
	} else if r.URL.Query().Get("error") == "failed" {
		data.Error = "Failed to add painting. Please try again."
	} else if r.URL.Query().Get("error") == "delete_failed" {
		data.Error = "Failed to delete painting. Please try again."
	} else if r.URL.Query().Get("error") == "upload_failed" {
		data.Error = "Failed to upload image. Please try again."
	}

	tmpl, err := template.ParseFiles("template/admin.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

// adminAddHandler adds a new painting
func adminAddHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	if _, loggedIn := getUserFromSession(r); !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		// Parse multipart form (for file upload)
		err := r.ParseMultipartForm(10 << 20) // 10 MB max
		if err != nil {
			log.Println("Error parsing form:", err)
			http.Redirect(w, r, "/admin?error=failed", http.StatusSeeOther)
			return
		}

		title := r.FormValue("title")
		artist := r.FormValue("artist")
		price := r.FormValue("price")
		description := r.FormValue("description")

		var imagePath string

		// Handle file upload
		file, handler, err := r.FormFile("image")
		if err == nil {
			// File was uploaded
			defer file.Close()

			// Create uploads directory if it doesn't exist
			err = os.MkdirAll("./static/uploads", os.ModePerm)
			if err != nil {
				log.Println("Error creating uploads directory:", err)
				http.Redirect(w, r, "/admin?error=upload_failed", http.StatusSeeOther)
				return
			}

			// Generate unique filename
			timestamp := time.Now().Unix()
			filename := fmt.Sprintf("%d_%s", timestamp, handler.Filename)
			imagePath = "/static/uploads/" + filename

			// Save file
			dst, err := os.Create("./static/uploads/" + filename)
			if err != nil {
				log.Println("Error creating file:", err)
				http.Redirect(w, r, "/admin?error=upload_failed", http.StatusSeeOther)
				return
			}
			defer dst.Close()

			_, err = io.Copy(dst, file)
			if err != nil {
				log.Println("Error saving file:", err)
				http.Redirect(w, r, "/admin?error=upload_failed", http.StatusSeeOther)
				return
			}

			fmt.Printf("Image uploaded: %s\n", filename)
		}

		_, err = db.Exec("INSERT INTO paintings (title, artist, price, description, image_path) VALUES (?, ?, ?, ?, ?)",
			title, artist, price, description, imagePath)

		if err != nil {
			log.Println("Error adding painting:", err)
			http.Redirect(w, r, "/admin?error=failed", http.StatusSeeOther)
			return
		}

		fmt.Printf("Painting '%s' added successfully!\n", title)
		http.Redirect(w, r, "/admin?success=added", http.StatusSeeOther)
	}
}

// adminDeleteHandler deletes a painting
func adminDeleteHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	if _, loggedIn := getUserFromSession(r); !loggedIn {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		// Get painting ID from URL path
		path := r.URL.Path
		id := path[len("/admin/delete/"):]

		_, err := db.Exec("DELETE FROM paintings WHERE id = ?", id)
		if err != nil {
			log.Println("Error deleting painting:", err)
			http.Redirect(w, r, "/admin?error=delete_failed", http.StatusSeeOther)
			return
		}

		fmt.Printf("Painting ID %s deleted successfully!\n", id)
		http.Redirect(w, r, "/admin?success=deleted", http.StatusSeeOther)
	}
}

func main() {
	// Initialize database
	if err := initDatabase(); err != nil {
		log.Fatal("Database initialization failed:", err)
	}
	defer db.Close()

	// Start session cleanup
	sessionCleanup()

	// Routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	})
	http.HandleFunc("/home", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/paintings", paintingsHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/logout", logoutHandler)

	// Admin routes
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/admin/add", adminAddHandler)
	http.HandleFunc("/admin/delete/", adminDeleteHandler)

	// Static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server running at: http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
