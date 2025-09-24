const db = require('./config/db');

async function checkUsers() {
    try {
        const [rows] = await db.execute('SELECT username, role FROM users');
        console.log('Пользователи в базе:', rows);
        process.exit(0);
    } catch (error) {
        console.error('Ошибка:', error.message);
        process.exit(1);
    }
}

checkUsers();