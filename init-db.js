// init-db.js
const db = require('./config/db');
const bcrypt = require('bcrypt');

async function initializeDatabase() {
  try {
    console.log('Подключение к базе данных...');

    // Создание таблицы пользователей
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin', 'user', 'viewer') NOT NULL DEFAULT 'user',
        can_upload_price BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Таблица users создана или уже существует.');

    // Создание таблицы прайс-листа
    await db.execute(`
      CREATE TABLE IF NOT EXISTS price_list (
        id INT AUTO_INCREMENT PRIMARY KEY,
        article VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        unit VARCHAR(100),
        price DECIMAL(10, 2) NOT NULL,
        brand VARCHAR(255),
        \`group\` VARCHAR(255),
        created_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_article_brand (article, brand)
      )
    `);
    console.log('Таблица price_list создана или уже существует.');

    // Создание таблицы заказов
    await db.execute(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        number VARCHAR(100) UNIQUE NOT NULL,
        date DATE NOT NULL,
        user VARCHAR(255) NOT NULL,
        comment TEXT,
        total DECIMAL(10, 2) DEFAULT 0.00,
        discount DECIMAL(5, 2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    console.log('Таблица orders создана или уже существует.');

    // Создание таблицы подзаказов
    await db.execute(`
      CREATE TABLE IF NOT EXISTS suborders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        total DECIMAL(10, 2) DEFAULT 0.00,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
      )
    `);
    console.log('Таблица suborders создана или уже существует.');

    // Создание таблицы позиций заказа
    await db.execute(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        suborder_id INT NOT NULL,
        article VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        brand VARCHAR(255),
        unit VARCHAR(100),
        price DECIMAL(10, 2) NOT NULL,
        quantity INT NOT NULL,
        total DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (suborder_id) REFERENCES suborders(id) ON DELETE CASCADE
      )
    `);
    console.log('Таблица order_items создана или уже существует.');

    // Создание таблицы наценок на бренды
    await db.execute(`
      CREATE TABLE IF NOT EXISTS order_brand_markups (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        brand VARCHAR(255) NOT NULL,
        markup DECIMAL(5, 2) NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        UNIQUE KEY unique_order_brand (order_id, brand)
      )
    `);
    console.log('Таблица order_brand_markups создана или уже существует.');

    // Создание таблицы глобальных наценок
    await db.execute(`
      CREATE TABLE IF NOT EXISTS global_brand_markups (
        id INT AUTO_INCREMENT PRIMARY KEY,
        brand VARCHAR(255) UNIQUE NOT NULL,
        markup DECIMAL(5, 2) NOT NULL
      )
    `);
    console.log('Таблица global_brand_markups создана или уже существует.');

    // Добавление тестовых пользователей
    const [users] = await db.execute('SELECT COUNT(*) AS count FROM users');
    if (users[0].count === 0) {
      const hashedAdminPassword = await bcrypt.hash('admin123', 10);
      const hashedUserPassword = await bcrypt.hash('user123', 10);
      const hashedViewerPassword = await bcrypt.hash('viewer123', 10);
      
      await db.execute(
        'INSERT INTO users (username, password, role, can_upload_price) VALUES (?, ?, ?, ?), (?, ?, ?, ?), (?, ?, ?, ?)',
        [
          'admin', hashedAdminPassword, 'admin', 1,
          'user', hashedUserPassword, 'user', 1,
          'viewer', hashedViewerPassword, 'viewer', 0
        ]
      );
      console.log('Тестовые пользователи добавлены.');
    }

    console.log('База данных успешно инициализирована.');
    process.exit(0);

  } catch (error) {
    console.error('Ошибка инициализации базы данных:', error);
    process.exit(1);
  }
}

initializeDatabase();