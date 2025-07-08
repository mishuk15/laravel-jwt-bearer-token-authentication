<p align="center"><a href="https://laravel.com" target="_blank"><img src="https://raw.githubusercontent.com/laravel/art/master/logo-lockup/5%20SVG/2%20CMYK/1%20Full%20Color/laravel-logolockup-cmyk-red.svg" width="400" alt="Laravel Logo"></a></p>

<p align="center">
<a href="https://github.com/laravel/framework/actions"><img src="https://github.com/laravel/framework/workflows/tests/badge.svg" alt="Build Status"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://img.shields.io/packagist/dt/laravel/framework" alt="Total Downloads"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://img.shields.io/packagist/v/laravel/framework" alt="Latest Stable Version"></a>
<a href="https://packagist.org/packages/laravel/framework"><img src="https://img.shields.io/packagist/l/laravel/framework" alt="License"></a>
</p>

## About Laravel

Laravel is a web application framework with expressive, elegant syntax. We believe development must be an enjoyable and creative experience to be truly fulfilling. Laravel takes the pain out of development by easing common tasks used in many web projects, such as:

- [Simple, fast routing engine](https://laravel.com/docs/routing).
- [Powerful dependency injection container](https://laravel.com/docs/container).
- Multiple back-ends for [session](https://laravel.com/docs/session) and [cache](https://laravel.com/docs/cache) storage.
- Expressive, intuitive [database ORM](https://laravel.com/docs/eloquent).
- Database agnostic [schema migrations](https://laravel.com/docs/migrations).
- [Robust background job processing](https://laravel.com/docs/queues).
- [Real-time event broadcasting](https://laravel.com/docs/broadcasting).

Laravel is accessible, powerful, and provides tools required for large, robust applications.

## Learning Laravel

Laravel has the most extensive and thorough [documentation](https://laravel.com/docs) and video tutorial library of all modern web application frameworks, making it a breeze to get started with the framework.

You may also try the [Laravel Bootcamp](https://bootcamp.laravel.com), where you will be guided through building a modern Laravel application from scratch.

If you don't feel like reading, [Laracasts](https://laracasts.com) can help. Laracasts contains thousands of video tutorials on a range of topics including Laravel, modern PHP, unit testing, and JavaScript. Boost your skills by digging into our comprehensive video library.

## Laravel Sponsors

We would like to extend our thanks to the following sponsors for funding Laravel development. If you are interested in becoming a sponsor, please visit the [Laravel Partners program](https://partners.laravel.com).

### Premium Partners

- **[Vehikl](https://vehikl.com)**
- **[Tighten Co.](https://tighten.co)**
- **[Kirschbaum Development Group](https://kirschbaumdevelopment.com)**
- **[64 Robots](https://64robots.com)**
- **[Curotec](https://www.curotec.com/services/technologies/laravel)**
- **[DevSquad](https://devsquad.com/hire-laravel-developers)**
- **[Redberry](https://redberry.international/laravel-development)**
- **[Active Logic](https://activelogic.com)**

## Contributing

Thank you for considering contributing to the Laravel framework! The contribution guide can be found in the [Laravel documentation](https://laravel.com/docs/contributions).

## Code of Conduct

In order to ensure that the Laravel community is welcoming to all, please review and abide by the [Code of Conduct](https://laravel.com/docs/contributions#code-of-conduct).

## Security Vulnerabilities

If you discover a security vulnerability within Laravel, please send an e-mail to Taylor Otwell via [taylor@laravel.com](mailto:taylor@laravel.com). All security vulnerabilities will be promptly addressed.

## License

The Laravel framework is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).

Absolutely — here’s a **clean, practical `README.md`** for your **Laravel JWT Auth API** project using **Pest** for testing.
This README is realistic for your setup (`tymon/jwt-auth`, Laravel 12, Pest, Postman, bootstrap/app.php).

---

## ✅ **`README.md`**

````md
# Laravel JWT Auth API

A simple **JWT authentication API** built with **Laravel 12** and **[tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth)**.

This project includes:
- Register
- Login
- Logout
- Get Authenticated User
- Update User
- Fully tested with **Pest**

---

## 📦 Requirements

- PHP >= 8.2
- Composer
- Laravel 12
- `tymon/jwt-auth`
- `pestphp/pest` for tests

---

## 🚀 Getting Started

### 1️⃣ Clone & install

```bash
git clone https://github.com/yourusername/laravel-jwt-auth.git
cd laravel-jwt-auth

composer install
````

---

### 2️⃣ Setup your `.env`

Copy `.env.example`:

```bash
cp .env.example .env
```

Generate key:

```bash
php artisan key:generate
```

Set your **database** credentials in `.env`:

```env
DB_CONNECTION=mysql
DB_DATABASE=your_db
DB_USERNAME=root
DB_PASSWORD=
```

---

### 3️⃣ Migrate

```bash
php artisan migrate
```

---

### 4️⃣ Generate JWT secret

```bash
php artisan jwt:secret
```

---

## ✅ API Endpoints

| Method | Endpoint        | Description                    |
| ------ | --------------- | ------------------------------ |
| POST   | `/api/register` | Register new user              |
| POST   | `/api/login`    | Login user                     |
| POST   | `/api/logout`   | Logout user (invalidate token) |
| GET    | `/api/user`     | Get authenticated user         |
| PUT    | `/api/user`     | Update authenticated user      |

All protected routes need an `Authorization: Bearer {token}` header.

---

## 🔑 Example Postman Setup

1. Register → POST `/api/register`
2. Copy the returned `token`
3. Use `Authorization: Bearer {token}` in header for:

   * GET `/api/user`
   * PUT `/api/user`
   * POST `/api/logout`

---

## ✅ Run Tests (Pest)

This project uses **Pest**.

Run all tests:

```bash
php artisan test
```

or directly:

```bash
./vendor/bin/pest
```

---

## 🧪 Test Coverage

Tests include:

* Register ✅
* Login ✅
* Login Fail ✅
* Get User ✅
* Update User ✅
* Logout ✅

---

## 🧰 Dev Tips

* Use `php artisan serve` to run the server.
* Use SQLite for fast tests: set `DB_CONNECTION=sqlite` and `DB_DATABASE=:memory:` in `phpunit.xml`.
* You can mix Pest & PHPUnit tests freely.

---

## 🫶 Credits

* [Laravel](https://laravel.com)
* [tymon/jwt-auth](https://github.com/tymondesigns/jwt-auth)
* [Pest](https://pestphp.com)

---

## 📝 License

MIT

```

---

## ✅ What’s included?

- 🚀 Easy **local setup**
- 🔑 JWT secret instructions
- ✅ Clear **API routes**
- 🧪 How to test with Pest
- 🧰 SQLite test hint
- 📌 Postman usage

---

If you want, I can:
- 📂 Generate a real **Postman collection JSON**
- ✅ Add `.env.example`
- ✅ Add a `Makefile` or `composer scripts`

Just say: **“Yes, Postman please!”** and I’ll package it up for you. 🔥
```

