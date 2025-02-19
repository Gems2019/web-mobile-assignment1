# COMP3795_Assignment1

This project is an assignment for **COMP3795** that demonstrates a simple CRUD (Create, Read, Update, Delete) system in PHP with SQLite. It includes user registration, login, user role management (Admin/Contributor), and basic blog article functionality.

## Member contribution
Brian Diep A00959233:
- Registration
- Password Encryption
- User Management
- Login/Logout
- UI
Gem Baojimin Sha A01345766
- Admin roles
- Contributor roles
- Access control
- Admin panal button for Admin only
- UI
Jason Hong A01232139
- Create Articles
- Edit function
- Display function
- Delete function
- Main page to show all the articles
- MyArticle function to show the article made by the user
- UI

---

## Table of Contents

- [Project Structure](#project-structure)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Database Structure](#database-structure)
- [Key Files](#key-files)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---
- **`inc_header.php`/`inc_footer.php`**: Common layout (header/footer) for pages.
- **`inc_db_params.php`**: Database initialization/connection.
- **`seed.php`**: Seeds default data (Users/Articles).
- **`landing-css.css`**: Main stylesheet for landing page styling.
- **`login/`** & **`register/`**: Authentication logic.
- **`admin/manage_users.php`**: Admin panel to manage users.
- **`crud/`**: Core CRUD operations (create, read, update, delete) for articles.
- **`contributor/`**: Additional contributor-specific views (e.g., their own articles).
- **`main.php`** or **`index.php`**: Entry pages displaying articles.

---

## Features

1. **User Authentication**  
   - Registration & Login system using a hashed password (`password_hash`).
   - Session-based login management.

2. **Role-Based Access**  
   - **Admin** can manage all users (approve, role change, delete).
   - **Contributor** can post and manage their own articles.

3. **CRUD for Articles**  
   - **Create** new articles (title, body, optional start/end dates).
   - **Read** articles on main/index pages.
   - **Update** articles for contributors or admins.
   - **Delete** articles (admin or article owner).

4. **SQLite Database**  
   - `blog3795.sqlite` stores Users & Articles.
   - `seed.php` sets up tables and default data (test users, default articles).

5. **Landing Page**  
   - A styled page (`landing-css.css`) with a responsive navbar, hero banner, and articles listing.

---

## Requirements

1. **PHP 8.0+** (recommended; works with older versions but be mindful of deprecation notices).  
2. **SQLite 3** extension enabled in PHP.  
3. A local server environment (e.g., XAMPP, MAMP, WAMP) or equivalent on Linux/Windows/macOS.  
4. A web browser.

---

## Installation

1. **Clone or Download** this repository into your local server’s document root.
   ```bash
   git clone https://github.com/JJasonHong/COMP3795_Assignment1.git