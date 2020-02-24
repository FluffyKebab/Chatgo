package main

import (
	"crypto/sha1"
	"database/sql"
	"fmt"
	"github.com/beevik/guid"
	_ "github.com/mattn/go-sqlite3"
	"html/template"
	"net/http"
	"strings"
	"time"
)

//DATABASE
var db *sql.DB

type User struct {
	ID         int    `json:"id"`
	Pass       string `json:"pass"`
	Username   string `json:"username"`
	UsersChats string `json:"userschats"`
	CookieVal  string `json:"cookieval"`
}

type AllChats struct {
	ID              int    `json:"id"`
	ChatName        string `json:"chatname"`
	ChatDescription string `json:"chatdescription"`
}

type AllMessages struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
	User    string `json:"user"`
	Chat    string `json:"chat"`
}

//DIV STUCTS
type Comment struct {
	Message  string
	Username string
	CssClass string
}

type CommentPage struct {
	ChatName string
	Status   string
	Messeges []Comment
}

type IndexPage struct {
	UserName string
	Chats    []ChatInfo
}

type ChatInfo struct {
	ChatName        string
	ChatDiscription string
	CssClass        string
}

type SearchPage struct {
	SearchTerm string
	NumRes     int
	Chats      []ChatInfo
}

//ANDRE FUNCS
func IfLogedIn(r *http.Request) bool {

	for _, cookie := range r.Cookies() {
		if cookie.Name == "SessionID" {
			var user User

			cookieSplit := strings.Split(cookie.Value, ":")

			row := db.QueryRow("SELECT * FROM users WHERE username = ? AND cookieval = ?", cookieSplit[0], cookieSplit[1])
			err := row.Scan(&user.ID, &user.Pass, &user.Username, &user.CookieVal, &user.UsersChats)

			if err == nil {
				return true
			}

			panic(err.Error())
		}
	}

	return false
}

func GetUsername(r *http.Request) string {
	for _, cookie := range r.Cookies() {
		if cookie.Name == "SessionID" {

			cookieSplit := strings.Split(cookie.Value, ":")
			return cookieSplit[0]
		}
	}

	return ""
}

func IfIsInChat(r *http.Request, chatname string) bool {
	username := GetUsername(r)

	row := db.QueryRow("SELECT userschats FROM users WHERE username = ?", username)

	var chats string
	err := row.Scan(&chats)
	if err != nil {
		panic(err.Error())
	}

	chatsSep := strings.Split(chats, "#")

	for _, c := range chatsSep {
		if c == chatname {
			return true
		}
	}

	return false
}

func EditChats(chatname, username string, add bool) {
	row := db.QueryRow("SELECT userschats FROM users WHERE username = ?", username)

	var oldChats string
	err := row.Scan(&oldChats)
	if err != nil {
		panic(err.Error())
	}

	var newChats string

	if add == true {
		newChats = oldChats + "#" + chatname
	}

	if add == false {
		newChats = strings.Replace(oldChats, "#"+chatname, "", -1)
	}

	fmt.Println("old chats: " + oldChats)
	fmt.Println("new chats: " + newChats)

	_, err = db.Exec("UPDATE users SET userschats = ? WHERE username = ?", newChats, username)
	if err != nil {
		panic(err.Error())
	}
}

func hash(s string) []byte {
	h := sha1.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

//LOGIN, SIGNUP, NEWCHAT OG NEWPOST
func Signup(pass, username, guid string) bool {

	row := db.QueryRow("SELECT * FROM users WHERE username = ?", username)
	var user User
	err := row.Scan(&user.ID, &user.Pass, &user.Username, &user.UsersChats, &user.CookieVal)

	if err != nil {
		if err == sql.ErrNoRows {

			pass = string(hash(pass))

			fmt.Println(pass)

			_, err = db.Exec(`INSERT INTO users (pass, username, cookieval, userschats) VALUES (?, ?, ?, "");`, pass, username, guid)
			if err != nil {
				panic(err.Error())
			}

			_, err = db.Exec(`UPDATE users SET userschats = ?;`, "")
			if err != nil {
				panic(err.Error())
			}

			return true
		}

		panic(err.Error())
	}

	return false
}

func Login(pass string, username string) bool {

	var user User

	row := db.QueryRow("SELECT * FROM users WHERE pass = ? AND username = ?", pass, username)
	err := row.Scan(&user.ID, &user.Pass, &user.Username, &user.CookieVal, &user.UsersChats)

	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}

		panic(err.Error())
	}

	return true
}

func NewChat(ChatName string, ChatDescription string) (bool, string) {

	var allchats AllChats

	row := db.QueryRow("SELECT * FROM allchats WHERE chatname = ?", ChatName)
	err := row.Scan(&allchats.ID, &allchats.ChatName, &allchats.ChatDescription)

	if err != nil {
		if err == sql.ErrNoRows {

			if ChatName == "" || ChatDescription == "" {
				return false, "Du mangeler en verdi"
			}

			for _, c := range ChatName {
				if string(c) == "#" {
					return false, "Kan ikke bruke # i chat navn"
				}
			}

			_, err = db.Exec(`INSERT INTO allchats (chatname, chatdescription) VALUES (?, ?);`, ChatName, ChatDescription)
			if err != nil {
				panic(err.Error())
			}

			return true, ""
		}

		panic(err.Error())
	}

	return false, "Chat navn opttat"
}

func NewPost(chatname, user, post string) {
	_, err := db.Exec(`INSERT INTO allmessages (chat, user, message) VALUES (?, ?, ?)`, chatname, user, post)
	if err != nil {
		panic(err.Error())
	}
}

//HANDLERS
func indexPage(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Index Page")

	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if IfLogedIn(r) == true {
		t, err := template.ParseFiles("src/indexLoggedIn.html")
		if err != nil {
			panic(err.Error())
		}

		username := GetUsername(r)

		var indexPage IndexPage
		indexPage.UserName = username

		row := db.QueryRow("SELECT userschats FROM users WHERE username = ?", username)

		var userschats string
		err = row.Scan(&userschats)
		if err != nil {
			panic(err.Error())
		}

		userschatsSlice := strings.Split(userschats, "#")

		fmt.Println(userschatsSlice)

		fmt.Println(len(userschatsSlice))

		if len(userschatsSlice) <= 1 {

			var chatInfo ChatInfo
			chatInfo.ChatName = "Du er ikke medlem i noen chatter"
			chatInfo.ChatDiscription = `Trykk "Join" på chater du liker så vises de her`
			chatInfo.CssClass = "block"

			indexPage.Chats = append(indexPage.Chats, chatInfo)

			fmt.Println(indexPage)

			t.Execute(w, indexPage)
			return
		}

		for _, c := range userschatsSlice {
			var chatInfo ChatInfo
			var chat AllChats

			row := db.QueryRow("SELECT * FROM allchats WHERE chatname = ?", c)
			err := row.Scan(&chat.ID, &chat.ChatName, &chat.ChatDescription)

			if err != nil {
				if err != sql.ErrNoRows {
					panic(err.Error())
				}

				chatInfo.CssClass = ""
			} else {
				chatInfo.CssClass = "block"
			}

			chatInfo.ChatName = chat.ChatName
			chatInfo.ChatDiscription = chat.ChatDescription

			indexPage.Chats = append(indexPage.Chats, chatInfo)
		}

		fmt.Println(indexPage)

		t.Execute(w, indexPage)
	}

	if IfLogedIn(r) == false {
		t, err := template.ParseFiles("src/indexNotLoggedIn.html")
		if err != nil {
			panic(err.Error())
		}

		t.Execute(w, nil)

	}
}

func loginPage(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Login page")

	if IfLogedIn(r) == true {
		http.Redirect(w, r, "./", 301)
	}

	if r.Method == "GET" {
		t, err := template.ParseFiles("src/login.html")
		if err != nil {
			panic(err.Error())
		}

		t.Execute(w, nil)

	}

	if r.Method == "POST" {

		r.ParseForm()

		password := r.Form["password"][0]
		username := r.Form["username"][0]

		result := Login(password, username)

		if result == false {
			fmt.Println("du feil passord")

			t, err := template.ParseFiles("src/login.html")
			if err != nil {
				panic(err.Error())
			}

			ItemsErr := struct {
				Error string
			}{
				Error: "Passord eller brukernavn feil",
			}

			t.Execute(w, ItemsErr)

			return
		}

		fmt.Println("yay du kom inn")

		var user User

		row := db.QueryRow("SELECT * FROM users WHERE username = ?", username)
		err := row.Scan(&user.ID, &user.Pass, &user.Username, &user.CookieVal, &user.UsersChats)
		if err != nil {
			panic(err.Error())
		}

		cookieValue := username + ":" + user.CookieVal
		expiration := time.Now().Add(365 * 24 * time.Hour)

		cookie := http.Cookie{
			Name:     "SessionID",
			Value:    cookieValue,
			Expires:  expiration,
			HttpOnly: true,
		}

		http.SetCookie(w, &cookie)

		http.Redirect(w, r, "./", 301)

	}
}

func signupPage(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Signing up page")

	if IfLogedIn(r) == true {
		http.Redirect(w, r, "./", 301)
		return
	}

	if r.Method == "GET" {
		t, err := template.ParseFiles("src/signup.html")
		if err != nil {
			panic(err.Error())
		}

		t.Execute(w, nil)
	}

	if r.Method == "POST" {
		r.ParseForm()

		password := r.Form["password"][0]
		username := r.Form["username"][0]

		guid := fmt.Sprintf(guid.New().String())

		sucseful := Signup(password, username, guid)

		if sucseful == false {

			t, err := template.ParseFiles("src/signup.html")
			if err != nil {
				panic(err.Error())
			}

			ItemsErr := struct {
				Error string
			}{
				Error: "brukernavn opptat",
			}

			t.Execute(w, ItemsErr)

			return
		}

		cookieValue := username + ":" + guid
		expiration := time.Now().Add(365 * 24 * time.Hour)

		cookie := http.Cookie{
			Name:     "SessionID",
			Value:    cookieValue,
			Expires:  expiration,
			HttpOnly: true,
		}

		http.SetCookie(w, &cookie)

		http.Redirect(w, r, "./", 301)
	}
}

func newChatPage(w http.ResponseWriter, r *http.Request) {

	if IfLogedIn(r) == false {
		http.Redirect(w, r, "./", 301)
		return
	}

	if r.Method == "GET" {
		t, err := template.ParseFiles("src/newChat.html")
		if err != nil {
			panic(err.Error())
		}

		t.Execute(w, nil)
	}

	if r.Method == "POST" {
		r.ParseForm()

		chatname := r.Form["chatname"][0]
		chatdiscription := r.Form["chatdiscription"][0]

		ok, what := NewChat(chatname, chatdiscription)

		if ok == false {
			t, err := template.ParseFiles("src/newChat.html")
			if err != nil {
				panic(err.Error())
			}

			ItemsErr := struct {
				Error string
			}{
				Error: what,
			}

			t.Execute(w, ItemsErr)

			return
		}

		link := "/chat?c=" + chatname

		http.Redirect(w, r, link, 301)
	}
}

func chatPage(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Velkomen til THE CHATPAGE")

	if IfLogedIn(r) == false {
		http.Redirect(w, r, "./", 301)
		return
	}

	chatnames, ok := r.URL.Query()["c"]
	if !ok || len(chatnames[0]) < 1 {
		http.Redirect(w, r, "./", 301)
		return
	}

	chatname := chatnames[0]

	if r.Method == "GET" {
		var allchats AllChats

		row := db.QueryRow("SELECT * FROM allchats WHERE chatname = ?", chatname)
		err := row.Scan(&allchats.ID, &allchats.ChatName, &allchats.ChatDescription)

		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "404 not found.", http.StatusNotFound)
				return
			}

			fmt.Println("HVAAA")
			panic(err.Error())
		}

		t, err := template.ParseFiles("src/chat.html")
		if err != nil {
			panic(err.Error())
		}

		var page CommentPage
		page.ChatName = chatname

		if IfIsInChat(r, chatname) == true {
			page.Status = "Leave Chat"
		} else {
			page.Status = "Join Chat"
		}

		rows, err := db.Query("SELECT * FROM allmessages WHERE chat = ?", chatname)
		if err != nil {
			panic(err.Error())
		}

		username := GetUsername(r)

		for rows.Next() {
			var item Comment

			var messages AllMessages
			rows.Scan(&messages.ID, &messages.Message, &messages.User, &messages.Chat)

			item.Message = messages.Message
			item.Username = messages.User

			if username == messages.User {
				item.CssClass = "message-your"
			} else {
				item.CssClass = "message-other"
			}

			page.Messeges = append(page.Messeges, item)

		}

		t.Execute(w, page)
	}

	if r.Method == "POST" {

		if IfIsInChat(r, chatname) == true {
			EditChats(chatname, GetUsername(r), false)
		} else {
			EditChats(chatname, GetUsername(r), true)
		}

		http.Redirect(w, r, r.Header.Get("Referer"), 302)

	}
}

func chatPost(w http.ResponseWriter, r *http.Request) {

	if IfLogedIn(r) == false {
		http.Redirect(w, r, "./", 301)
		return
	}

	chatnames, ok := r.URL.Query()["c"]
	if !ok || len(chatnames[0]) < 1 {
		fmt.Println("FANT IKKE")

		return
	}

	chatname := chatnames[0]

	if r.Method == "POST" {

		fmt.Println("NÅ ble det sent en post til chatte greia")

		r.ParseForm()

		post := r.Form["message"][0]
		username := GetUsername(r)

		NewPost(chatname, username, post)

		http.Redirect(w, r, r.Header.Get("Referer"), 302)

	}
}

func search(w http.ResponseWriter, r *http.Request) {

	if IfLogedIn(r) == false {
		http.Redirect(w, r, "./", 301)
		return
	}

	searchTerms, ok := r.URL.Query()["s"]
	if !ok || len(searchTerms[0]) < 1 {
		fmt.Println("FANT IKKE")
		http.Redirect(w, r, r.Header.Get("Referer"), 302)
		return
	}

	searchTerm := searchTerms[0]

	t, err := template.ParseFiles("src/search.html")
	if err != nil {
		panic(err.Error())
	}

	var page SearchPage
	page.SearchTerm = searchTerm

	rows, err := db.Query("SELECT * FROM allchats WHERE chatname LIKE ?", "%"+searchTerm+"%")
	if err != nil {
		panic(err.Error())
	}

	for rows.Next() {
		var chats AllChats
		var item ChatInfo

		page.NumRes = page.NumRes + 1

		rows.Scan(&chats.ID, &chats.ChatName, &chats.ChatDescription)

		item.ChatName = chats.ChatName
		item.ChatDiscription = chats.ChatDescription

		page.Chats = append(page.Chats, item)
	}

	t.Execute(w, page)
}

func newestPage(w http.ResponseWriter, r *http.Request) {

	fmt.Println("NEWEST page")

	if IfLogedIn(r) == false {
		http.Redirect(w, r, "./", 301)
		fmt.Println("KSKS")
		return
	}

	fmt.Println("joa")

	t, err := template.ParseFiles("src/newest.html")
	if err != nil {
		panic(err.Error())
	}

	var page IndexPage

	rows, err := db.Query("SELECT * FROM (SELECT * FROM allchats ORDER BY id DESC LIMIT 0, 25)s ORDER BY id ASC ")
	if err != nil {
		panic(err.Error())
	}

	for rows.Next() {

		var chats AllChats
		var chat ChatInfo

		err := rows.Scan(&chats.ID, &chats.ChatName, &chats.ChatDescription)
		if err != nil {
			panic(err.Error())
		}

		chat.ChatName = chats.ChatName
		chat.ChatDiscription = chats.ChatDescription

		page.Chats = append(page.Chats, chat)
	}

	t.Execute(w, page)
}

func main() {
	var err error

	fmt.Println("Åpner databasen")
	db, err = sql.Open("sqlite3", "./data.db")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Lager users tabel")
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, pass STRING, username STRING, cookieval STRING, userschats STRING);")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Lager AllChats tabel")
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS allchats (id INTEGER PRIMARY KEY AUTOINCREMENT, chatname STRING, chatdescription STRING);")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Lager AllMessages tabel")
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS allmessages (id INTEGER PRIMARY KEY AUTOINCREMENT, message STRING, user STRING, chat STRING);")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("")

	mux := http.NewServeMux()

	mux.HandleFunc("/", indexPage)
	mux.HandleFunc("/logins", loginPage)
	mux.HandleFunc("/signups", signupPage)
	mux.HandleFunc("/new", newChatPage)
	mux.HandleFunc("/chat", chatPage)
	mux.HandleFunc("/chatPost", chatPost)
	mux.HandleFunc("/search", search)
	mux.HandleFunc("/newestchat", newestPage)

	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		panic(err.Error())
	}
}
