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
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var tmpl *template.Template // FIXED: Added this missing variable

var sessions = make(map[string]string)

type Painting struct {
	ID          int
	Title       string
	Artist      string
	Year        string
	Medium      string
	Dimensions  string
	Price       int
	Description string
	ImagePath   string
	Image2      string
	Image3      string
}

type User struct {
	ID        int
	Email     string
	Password  string
	Name      string
	Phone     string
	Address   string
	Pincode   string
	CreatedAt string // FIXED: Added this missing field
}

type Order struct {
	ID           int
	UserEmail    string
	OrderID      string
	TotalAmount  int
	Status       string
	CreatedAt    string
	DeliveryDate string
	ShippingAddr string
}

type PageData struct {
	LoggedIn bool
	UserName string
	IsAdmin  bool
	Error    string
	Success  string

	Email string
	Name  string

	User          User
	Paintings     []Painting
	Painting      Painting
	Users         []User
	CartItems     []CartItem
	Total         int
	Order         Order
	Orders        []Order
	RazorpayKeyID string
	Search        string
	Sort          string
}

type CartItem struct {
	ID         int
	UserEmail  string
	PaintingID int
	Quantity   int
	Painting   Painting
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func getSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func getUserFromSession(r *http.Request) (string, bool) {
	sessionToken := getSessionCookie(r)
	if sessionToken == "" {
		return "", false
	}
	email, exists := sessions[sessionToken]
	if !exists {
		return "", false
	}
	var name string
	err := db.QueryRow("SELECT name FROM users WHERE email = ?", email).Scan(&name)
	if err != nil {
		return "", false
	}
	return name, true
}

func isAdminUser(r *http.Request) bool {
	sessionToken := getSessionCookie(r)
	if sessionToken == "" {
		return false
	}
	email, exists := sessions[sessionToken]
	if !exists {
		return false
	}
	var isAdmin int
	err := db.QueryRow("SELECT is_admin FROM users WHERE email = ?", email).Scan(&isAdmin)
	if err != nil {
		return false
	}
	return isAdmin == 1
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	userName, loggedIn := getUserFromSession(r)
	data := PageData{
		LoggedIn: loggedIn,
		UserName: userName,
		IsAdmin:  isAdminUser(r),
	}
	tmpl.ExecuteTemplate(w, "home.html", data)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if _, loggedIn := getUserFromSession(r); loggedIn {
			http.Redirect(w, r, "/paintings", http.StatusSeeOther)
			return
		}
		tmpl.ExecuteTemplate(w, "login.html", PageData{})
	} else if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		var dbPassword string
		var name string
		err := db.QueryRow("SELECT name, password FROM users WHERE email = ?", email).Scan(&name, &dbPassword)
		if err != nil {
			tmpl.ExecuteTemplate(w, "login.html", PageData{Error: "Invalid email or password", Email: email})
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			tmpl.ExecuteTemplate(w, "login.html", PageData{Error: "Invalid email or password", Email: email})
			return
		}
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
		fmt.Printf("User %s logged in successfully!\n", name)
		http.Redirect(w, r, "/paintings", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	if sessionToken != "" {
		delete(sessions, sessionToken)
	}
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

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if _, loggedIn := getUserFromSession(r); loggedIn {
			http.Redirect(w, r, "/paintings", http.StatusSeeOther)
			return
		}
		tmpl.ExecuteTemplate(w, "register.html", PageData{})
	} else if r.Method == "POST" {
		name := r.FormValue("name")
		email := r.FormValue("email")
		password := r.FormValue("password")
		if len(password) < 6 {
			tmpl.ExecuteTemplate(w, "register.html", PageData{Error: "Password must be at least 6 characters long", Name: name, Email: email})
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Could not process password", http.StatusInternalServerError)
			return
		}
		_, err = db.Exec("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", name, email, string(hashedPassword))
		if err != nil {
			tmpl.ExecuteTemplate(w, "register.html", PageData{Error: "Email already exists or registration failed", Name: name, Email: email})
			return
		}
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

func paintingsHandler(w http.ResponseWriter, r *http.Request) {
	userName, loggedIn := getUserFromSession(r)
	searchQuery := r.URL.Query().Get("search")
	sortBy := r.URL.Query().Get("sort")

	// Build the query with search filter
	query := "SELECT id, title, artist, COALESCE(year,''),COALESCE(medium,''),COALESCE(dimensions,''), price, COALESCE(description,''), COALESCE(image_path,''), COALESCE(image2,''), COALESCE(image3,''), created_at FROM paintings"
	var args []interface{}

	if searchQuery != "" {
		query += " WHERE title LIKE ? OR artist LIKE ?"
		searchPattern := "%" + searchQuery + "%"
		args = append(args, searchPattern, searchPattern)
	}

	// Add sorting
	switch sortBy {
	case "price_low":
		query += " ORDER BY price ASC"
	case "price_high":
		query += " ORDER BY price DESC"
	case "title":
		query += " ORDER BY title ASC"
	case "newest":
		query += " ORDER BY created_at DESC"
	default:
		query += " ORDER BY created_at DESC"
	}

	rows, err := db.Query(query, args...)

	if err != nil {
		log.Println("Paintings query error:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var paintings []Painting
	for rows.Next() {
		var p Painting
		var createdAt string
		rows.Scan(&p.ID, &p.Title, &p.Artist, &p.Year, &p.Medium, &p.Dimensions, &p.Price, &p.Description, &p.ImagePath, &p.Image2, &p.Image3, &createdAt)
		paintings = append(paintings, p)
	}

	data := PageData{
		LoggedIn:  loggedIn,
		UserName:  userName,
		IsAdmin:   isAdminUser(r),
		Paintings: paintings,
		Search:    searchQuery,
		Sort:      sortBy,
	}

	tmpl.ExecuteTemplate(w, "paintings.html", data)
}

func initDatabase() error {
	var err error
	db, err = sql.Open("sqlite3", "./gallery.db")
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		phone TEXT,
		address TEXT,
		pincode TEXT,
		is_admin INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS paintings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		artist TEXT NOT NULL,
		year TEXT,
		medium TEXT,
		dimensions TEXT,
		price INTEGER NOT NULL,
		description TEXT,
		image_path TEXT,
		image2 TEXT, 
		image3 TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cart (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		painting_id INTEGER NOT NULL,
		quantity INTEGER DEFAULT 1,
		added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (painting_id) REFERENCES paintings(id)
	)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		order_id TEXT UNIQUE NOT NULL,
		razorpay_order_id TEXT,
		razorpay_payment_id TEXT,
		total_amount INTEGER NOT NULL,
		status TEXT DEFAULT 'pending',
		shipping_address TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		delivered_at DATETIME,
		FOREIGN KEY (user_email) REFERENCES users(email)
	)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS order_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id TEXT NOT NULL,
		painting_id INTEGER NOT NULL,
		quantity INTEGER,
		price INTEGER,
		FOREIGN KEY (order_id) REFERENCES orders(order_id),
		FOREIGN KEY (painting_id) REFERENCES paintings(id)
	)`)
	if err != nil {
		return err
	}

	return nil
}

func sessionCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			fmt.Println("Session cleanup running...")
		}
	}()
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdminUser(r) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	userName, _ := getUserFromSession(r)

	if r.Method == "POST" {
		// Parse the form (up to 10MB)
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			http.Redirect(w, r, "/admin?error=upload_failed", http.StatusSeeOther)
			return
		}

		// 1. Get Text Data
		title := r.FormValue("title")
		artist := r.FormValue("artist")
		year := r.FormValue("date_year")
		medium := r.FormValue("medium")
		dimensions := r.FormValue("dimensions")
		price, _ := strconv.Atoi(r.FormValue("price"))
		description := r.FormValue("description")

		// 2. Handle the 3 Images using our helper
		img1 := saveFile(r, "image1")
		img2 := saveFile(r, "image2")
		img3 := saveFile(r, "image3")

		// 3. Insert into Database
		_, err = db.Exec(`INSERT INTO paintings 
            (title, artist, year, medium, dimensions, price, description, image_path, image2, image3) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			title, artist, year, medium, dimensions, price, description, img1, img2, img3)

		if err != nil {
			log.Println("Database Insert Error:", err)
			http.Redirect(w, r, "/admin?error=failed", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/admin?success=added", http.StatusSeeOther)
		return
	}

	// GET Request Logic (Fetching data for the table)
	rows, err := db.Query("SELECT id, title, artist, COALESCE(year,''), COALESCE(medium,''), COALESCE(dimensions,''), price, COALESCE(description,''), COALESCE(image_path,'') FROM paintings ORDER BY id")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var paintings []Painting
	for rows.Next() {
		var p Painting
		rows.Scan(&p.ID, &p.Title, &p.Artist, &p.Year, &p.Medium, &p.Dimensions, &p.Price, &p.Description, &p.ImagePath)
		paintings = append(paintings, p)
	}

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
		LoggedIn:  true,
		IsAdmin:   true,
		UserName:  userName,
		Paintings: paintings,
		Users:     users,
	}

	// Check URL parameters for Success/Error messages
	msg := r.URL.Query().Get("success")
	if msg == "added" {
		data.Success = "Painting added successfully!"
	}
	if msg == "deleted" {
		data.Success = "Painting removed!"
	}

	errMsg := r.URL.Query().Get("error")
	if errMsg == "failed" {
		data.Error = "Database error. Check your inputs."
	}

	tmpl.ExecuteTemplate(w, "admin.html", data)
}

func adminDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdminUser(r) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}
	if r.Method == "POST" {
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

func adminEditHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdminUser(r) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	path := r.URL.Path
	idStr := strings.TrimPrefix(path, "/admin/edit/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		var p Painting
		err := db.QueryRow("SELECT id, title, artist, COALESCE(year,''), COALESCE(medium,''), COALESCE(dimensions,''), price, COALESCE(description,''), COALESCE(image_path,'') FROM paintings WHERE id = ?", id).
			Scan(&p.ID, &p.Title, &p.Artist, &p.Year, &p.Medium, &p.Dimensions, &p.Price, &p.Description, &p.ImagePath)
		if err != nil {
			log.Println("Error fetching painting for edit:", err)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		data := PageData{
			LoggedIn: true,
			IsAdmin:  true,
			Painting: p,
		}
		tmpl.ExecuteTemplate(w, "edit.html", data)

	} else if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		title := r.FormValue("title")
		artist := r.FormValue("artist")
		year := r.FormValue("date_year")
		medium := r.FormValue("medium")
		dimensions := r.FormValue("dimensions")
		price := r.FormValue("price")
		description := r.FormValue("description")

		file, handler, err := r.FormFile("image")
		if err == nil {
			defer file.Close()
			err = os.MkdirAll("./static/uploads", os.ModePerm)
			if err != nil {
				http.Redirect(w, r, "/admin?error=upload_failed", http.StatusSeeOther)
				return
			}
			timestamp := time.Now().Unix()
			filename := fmt.Sprintf("%d_%s", timestamp, handler.Filename)
			newImagePath := filename
			dst, err := os.Create("./static/uploads/" + filename)
			if err != nil {
				http.Redirect(w, r, "/admin?error=upload_failed", http.StatusSeeOther)
				return
			}
			defer dst.Close()
			io.Copy(dst, file)

			_, err = db.Exec("UPDATE paintings SET title=?, artist=?, year=?, medium=?, dimensions=?, price=?, description=?, image_path=? WHERE id=?",
				title, artist, year, medium, dimensions, price, description, newImagePath, id)
		} else {
			_, err = db.Exec("UPDATE paintings SET title=?, artist=?, year=?, medium=?, dimensions=?, price=?, description=? WHERE id=?",
				title, artist, year, medium, dimensions, price, description, id)
		}

		if err != nil {
			log.Println("Error updating painting:", err)
			http.Redirect(w, r, "/admin?error=failed", http.StatusSeeOther)
			return
		}

		fmt.Printf("Painting ID %d updated successfully!\n", id)
		http.Redirect(w, r, "/admin?success=edited", http.StatusSeeOther)
	}
}

func addToCartHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	if sessionToken == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email, exists := sessions[sessionToken]
	if !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/add-to-cart/")

	var count int
	db.QueryRow("SELECT COUNT(*) FROM cart WHERE user_email = ? AND painting_id = ?",
		email, id).Scan(&count)

	if count > 0 {
		db.Exec("UPDATE cart SET quantity = quantity + 1 WHERE user_email = ? AND painting_id = ?",
			email, id)
	} else {
		db.Exec("INSERT INTO cart (user_email, painting_id) VALUES (?, ?)",
			email, id)
	}

	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

func cartHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email := sessions[sessionToken]

	// Join the cart with paintings so we have prices and titles
	rows, err := db.Query(`
        SELECT c.id, c.painting_id, c.quantity, 
               p.title, p.artist, p.price, p.image_path
        FROM cart c
        JOIN paintings p ON c.painting_id = p.id
        WHERE c.user_email = ?`, email)

	if err != nil {
		log.Println("Cart Query Error:", err)
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	var items []CartItem
	var total int

	for rows.Next() {
		var item CartItem
		// Very important: Scan into item.Painting fields!
		err := rows.Scan(&item.ID, &item.PaintingID, &item.Quantity,
			&item.Painting.Title, &item.Painting.Artist,
			&item.Painting.Price, &item.Painting.ImagePath)

		if err != nil {
			log.Println("Cart Scan Error:", err)
			continue
		}

		total += item.Painting.Price * item.Quantity
		items = append(items, item)
	}

	data := PageData{
		LoggedIn:  true,
		CartItems: items, // This connects Go data to {{range .CartItems}}
		Total:     total,
	}

	if err := tmpl.ExecuteTemplate(w, "cart.html", data); err != nil {
		log.Println("cart template exec:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func removeFromCartHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email := sessions[sessionToken]

	id := strings.TrimPrefix(r.URL.Path, "/remove-from-cart/")

	db.Exec("DELETE FROM cart WHERE id = ? AND user_email = ?", id, email)

	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

// saveFile handles individual file uploads for the 3 different image slots
func saveFile(r *http.Request, fieldName string) string {
	file, handler, err := r.FormFile(fieldName)
	if err != nil {
		return "" // Return empty if image wasn't uploaded (optional images)
	}
	defer file.Close()

	// Create unique filename
	fileName := fmt.Sprintf("%d_%s", time.Now().UnixNano(), handler.Filename)

	// Ensure directory exists
	os.MkdirAll("./static/uploads", os.ModePerm)

	dst, err := os.Create("./static/uploads/" + fileName)
	if err != nil {
		log.Println("Error creating file:", err)
		return ""
	}
	defer dst.Close()

	io.Copy(dst, file)
	return fileName
}

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email, exists := sessions[sessionToken]
	if sessionToken == "" || !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		// Get user details
		var u User
		db.QueryRow("SELECT email, name, phone, address, pincode FROM users WHERE email = ?", email).Scan(&u.Email, &u.Name, &u.Phone, &u.Address, &u.Pincode)

		// Get cart items and total
		rows, _ := db.Query(`
			SELECT c.id, c.painting_id, c.quantity, p.title, p.artist, p.price, p.image_path
			FROM cart c
			JOIN paintings p ON c.painting_id = p.id
			WHERE c.user_email = ?`, email)
		defer rows.Close()

		var items []CartItem
		var total int
		for rows.Next() {
			var item CartItem
			rows.Scan(&item.ID, &item.PaintingID, &item.Quantity, &item.Painting.Title, &item.Painting.Artist, &item.Painting.Price, &item.Painting.ImagePath)
			total += item.Painting.Price * item.Quantity
			items = append(items, item)
		}

		data := PageData{
			LoggedIn:      true,
			User:          u,
			CartItems:     items,
			Total:         total,
			RazorpayKeyID: "YOUR_RAZORPAY_KEY_ID", // Replace with your key
		}

		tmpl.ExecuteTemplate(w, "checkout.html", data)
		return
	}

	// POST: Create Razorpay order
	r.ParseForm()
	_ = r.FormValue("phone")
	address := r.FormValue("address")
	pincode := r.FormValue("pincode")

	// Get cart total
	var total int
	db.QueryRow("SELECT COALESCE(SUM(c.quantity * p.price), 0) FROM cart c JOIN paintings p ON c.painting_id = p.id WHERE c.user_email = ?", email).Scan(&total)

	// Generate order ID
	orderID := "ORD" + strings.ToUpper(fmt.Sprintf("%x", time.Now().UnixNano())[0:8])

	// Insert order into DB
	_, err := db.Exec(`INSERT INTO orders (user_email, order_id, total_amount, status, shipping_address) 
	VALUES (?, ?, ?, 'pending', ?)`, email, orderID, total, address+", "+pincode)

	if err != nil {
		log.Println("Order creation error:", err)
		http.Error(w, "Order creation failed", 500)
		return
	}

	log.Println("Order created:", orderID, "Amount:", total, "Email:", email)

	// Respond with order details for Razorpay
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"order_id":"%s","amount":%d}`, orderID, total*100)
}

func paymentVerifyHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email, exists := sessions[sessionToken]
	if sessionToken == "" || !exists {
		log.Println("Payment verify: not authenticated")
		http.Error(w, "Unauthorized", 401)
		return
	}

	r.ParseForm()
	orderID := r.FormValue("order_id")
	paymentID := r.FormValue("payment_id")

	log.Println("Payment verify: Order ID:", orderID, "Payment ID:", paymentID, "Email:", email)

	// Update order with payment details
	result, err := db.Exec(`UPDATE orders SET razorpay_payment_id = ?, status = 'paid' WHERE order_id = ? AND user_email = ?`, paymentID, orderID, email)

	if err != nil {
		log.Println("Payment verification error:", err)
		http.Error(w, "Payment verification failed", 500)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	log.Println("Rows affected by update:", rowsAffected)

	// Move cart items to order_items
	cartRows, _ := db.Query("SELECT painting_id, quantity FROM cart WHERE user_email = ?", email)
	for cartRows.Next() {
		var paintingID, qty int
		cartRows.Scan(&paintingID, &qty)
		var price int
		db.QueryRow("SELECT price FROM paintings WHERE id = ?", paintingID).Scan(&price)
		db.Exec("INSERT INTO order_items (order_id, painting_id, quantity, price) VALUES (?, ?, ?, ?)", orderID, paintingID, qty, price)
	}
	cartRows.Close()

	// Clear cart
	db.Exec("DELETE FROM cart WHERE user_email = ?", email)

	log.Println("Payment verified and order items created for:", orderID)

	// Return success
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"success":true,"order_id":"%s"}`, orderID)
}

func orderConfirmationHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email, exists := sessions[sessionToken]
	if sessionToken == "" || !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	orderID := strings.TrimPrefix(r.URL.Path, "/order-confirmation/")

	// Get order details
	var order Order
	err := db.QueryRow("SELECT id, order_id, total_amount, status, created_at FROM orders WHERE order_id = ? AND user_email = ?", orderID, email).Scan(&order.ID, &order.OrderID, &order.TotalAmount, &order.Status, &order.CreatedAt)

	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get order items
	rows, _ := db.Query("SELECT p.title, p.artist, oi.quantity, oi.price FROM order_items oi JOIN paintings p ON oi.painting_id = p.id WHERE oi.order_id = ?", orderID)
	defer rows.Close()

	var items []CartItem
	for rows.Next() {
		var item CartItem
		rows.Scan(&item.Painting.Title, &item.Painting.Artist, &item.Quantity, &item.Painting.Price)
		items = append(items, item)
	}

	data := PageData{
		LoggedIn:  true,
		Order:     order,
		CartItems: items,
	}

	tmpl.ExecuteTemplate(w, "order-confirmation.html", data)
}

func myOrdersHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email, exists := sessions[sessionToken]
	if sessionToken == "" || !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rows, _ := db.Query("SELECT id, order_id, total_amount, status, created_at FROM orders WHERE user_email = ? ORDER BY created_at DESC", email)
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var order Order
		rows.Scan(&order.ID, &order.OrderID, &order.TotalAmount, &order.Status, &order.CreatedAt)
		orders = append(orders, order)
	}

	data := PageData{
		LoggedIn: true,
		Orders:   orders,
	}

	tmpl.ExecuteTemplate(w, "my-orders.html", data)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email, exists := sessions[sessionToken]
	if sessionToken == "" || !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		var u User
		// Ensure the Scan matches the SELECT exactly
		err := db.QueryRow(`
        SELECT id, email, COALESCE(name,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(pincode,'')
        FROM users WHERE email = ?`, email).Scan(&u.ID, &u.Email, &u.Name, &u.Phone, &u.Address, &u.Pincode)

		if err != nil {
			log.Println("Profile Fetch Error:", err)
		}

		data := PageData{
			LoggedIn: true,
			User:     u,
		}
		if r.URL.Query().Get("success") == "true" {
			data.Success = "Profile updated successfully!"
		}
		
		// Handle error messages
		if errorParam := r.URL.Query().Get("error"); errorParam != "" {
			data.Error = errorParam
		}
		
		// Handle password-specific success message
		if r.URL.Query().Get("success") == "password_changed" {
			data.Success = "password_changed"
		}

		if err := tmpl.ExecuteTemplate(w, "profile.html", data); err != nil {
			log.Println("template exec:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	// POST Logic: Update the database
	name := r.FormValue("name")
	phone := r.FormValue("phone")
	address := r.FormValue("address")
	pincode := r.FormValue("pincode")

	_, err := db.Exec(`UPDATE users SET name=?, phone=?, address=?, pincode=? WHERE email=?`,
		name, phone, address, pincode, email)

	if err != nil {
		log.Println("Update error:", err)
		http.Redirect(w, r, "/profile?error=failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/profile?success=true", http.StatusSeeOther)
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	sessionToken := getSessionCookie(r)
	email, exists := sessions[sessionToken]
	if sessionToken == "" || !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	// POST: Handle password change
	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Validation: New passwords must match
	if newPassword != confirmPassword {
		http.Redirect(w, r, "/profile?error=passwords_dont_match", http.StatusSeeOther)
		return
	}

	// Validation: New password must not be same as old
	if oldPassword == newPassword {
		http.Redirect(w, r, "/profile?error=same_password", http.StatusSeeOther)
		return
	}

	// Fetch current password hash from DB
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE email = ?", email).Scan(&hashedPassword)
	if err != nil {
		log.Println("Password fetch error:", err)
		http.Redirect(w, r, "/profile?error=user_not_found", http.StatusSeeOther)
		return
	}

	// Verify old password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(oldPassword))
	if err != nil {
		// Old password is incorrect
		http.Redirect(w, r, "/profile?error=old_password_incorrect", http.StatusSeeOther)
		return
	}

	// Hash new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Password hashing error:", err)
		http.Redirect(w, r, "/profile?error=failed", http.StatusSeeOther)
		return
	}

	// Update password in database
	_, err = db.Exec("UPDATE users SET password = ? WHERE email = ?", string(hashedNewPassword), email)
	if err != nil {
		log.Println("Password update error:", err)
		http.Redirect(w, r, "/profile?error=update_failed", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/profile?success=password_changed", http.StatusSeeOther)
}

func main() {
	if err := initDatabase(); err != nil {
		log.Fatal("Database initialization failed:", err)
	}
	defer db.Close()

	sessionCleanup()

	// FIXED: Load templates correctly
	funcMap := template.FuncMap{
		"mul": func(a, b int) int { return a * b },
	}

	// Parse all templates
	tmpl = template.Must(template.New("").Funcs(funcMap).ParseFiles(
		"template/admin.html",
		"template/home.html",
		"template/paintings.html",
		"template/login.html",
		"template/register.html",
		"template/cart.html",
		"template/profile.html",
		"template/edit.html",
		"template/checkout.html",
		"template/order-confirmation.html",
		"template/my-orders.html",
	))

	// Debug: Print loaded templates
	fmt.Println("Loaded templates:")
	for _, t := range tmpl.Templates() {
		fmt.Println(" -", t.Name())
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	})

	http.HandleFunc("/home", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/paintings", paintingsHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/logout", logoutHandler)

	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/admin/delete/", adminDeleteHandler)
	http.HandleFunc("/admin/edit/", adminEditHandler)

	http.HandleFunc("/cart", cartHandler)
	http.HandleFunc("/add-to-cart/", addToCartHandler)
	http.HandleFunc("/remove-from-cart/", removeFromCartHandler)

	http.HandleFunc("/checkout", checkoutHandler)
	http.HandleFunc("/payment-verify", paymentVerifyHandler)
	http.HandleFunc("/order-confirmation/", orderConfirmationHandler)
	http.HandleFunc("/my-orders", myOrdersHandler)

	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/change-password", changePasswordHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server running at: http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
