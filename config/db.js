// config/db.js
require('dotenv').config(); // Для загрузки переменных окружения из .env файла (опционально)
const mysql = require('mysql2');

// Создаем пул соединений к базе данных
// Значения по умолчанию, замените их на свои
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'your_mysql_user',
  password: process.env.DB_PASSWORD || 'your_mysql_password',
  database: process.env.DB_NAME || 'order_management_db', // Имя вашей базы данных
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Экспортируем пул для использования в других файлах
module.exports = pool.promise(); // Используем promise() обертку для async/await