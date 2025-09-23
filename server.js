// server.js
const express = require('express');
const path = require('path');
const cors = require('cors');
const db = require('./config/db');
const bcrypt = require('bcrypt');
const XLSX = require('xlsx');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Middleware для проверки авторизации
const requireAuth = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    next();
};

// --- API Endpoints ---

// Проверка авторизации
app.post('/api/auth', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Имя пользователя и пароль обязательны' });
    }

    try {
        const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
        }

        // Создаем простой токен (в реальном приложении используйте JWT)
        const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');

        res.json({
            success: true,
            token: token,
            user: {
                username: user.username,
                role: user.role,
                canUploadPrice: user.can_upload_price === 1
            }
        });
    } catch (error) {
        console.error('Ошибка авторизации:', error);
        res.status(500).json({ error: 'Ошибка сервера при авторизации' });
    }
});

// Проверка токена
app.post('/api/verify-token', async (req, res) => {
    const { token, username } = req.body;

    if (!token || !username) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        // В реальном приложении здесь должна быть проверка JWT токена
        res.json({
            success: true,
            user: {
                username: users[0].username,
                role: users[0].role,
                canUploadPrice: users[0].can_upload_price === 1
            }
        });
    } catch (error) {
        console.error('Ошибка проверки токена:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получение прайс-листа
app.get('/api/price-list', async (req, res) => {
    try {
        const [priceListRows] = await db.execute('SELECT * FROM price_list');
        const priceList = priceListRows.map(row => ({
            article: row.article,
            name: row.name,
            unit: row.unit,
            price: row.price,
            brand: row.brand,
            group: row.group,
            createdBy: row.created_by,
            createdAt: row.created_at
        }));

        res.json(priceList);
    } catch (error) {
        console.error('Ошибка получения прайс-листа:', error);
        res.status(500).json({ error: 'Ошибка сервера при получении прайс-листа' });
    }
});

// Загрузка прайс-листа (для пользователей с правами)
app.post('/api/price-list', async (req, res) => {
    const { priceList, username } = req.body;

    if (!username) {
        return res.status(401).json({ error: 'Необходима авторизация' });
    }

    try {
        const [users] = await db.execute('SELECT role, can_upload_price FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        const user = users[0];
        if (user.role !== 'admin' && user.can_upload_price !== 1) {
            return res.status(403).json({ error: 'Недостаточно прав для загрузки прайс-листа' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            for (const item of priceList) {
                const price = parseFloat(item['Цена с НДС'] || item.price);
                const validPrice = isNaN(price) ? 0 : price;

                // Проверяем, существует ли уже товар с таким артикулом и брендом
                const [existing] = await connection.execute(
                    'SELECT id FROM price_list WHERE article = ? AND brand = ?',
                    [item.Артикул || item.article, item.Бренд || item.brand]
                );

                if (existing.length > 0) {
                    // Обновляем существующий товар
                    await connection.execute(
                        'UPDATE price_list SET name = ?, unit = ?, price = ?, `group` = ?, created_by = ? WHERE article = ? AND brand = ?',
                        [
                            item.Наименование || item.name,
                            item['Единица измерения'] || item.unit,
                            validPrice,
                            item.Группа || item.group,
                            username,
                            item.Артикул || item.article,
                            item.Бренд || item.brand
                        ]
                    );
                } else {
                    // Добавляем новый товар
                    await connection.execute(
                        'INSERT INTO price_list (article, name, unit, price, brand, `group`, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [
                            item.Артикул || item.article,
                            item.Наименование || item.name,
                            item['Единица измерения'] || item.unit,
                            validPrice,
                            item.Бренд || item.brand,
                            item.Группа || item.group,
                            username
                        ]
                    );
                }
            }

            await connection.commit();
            res.json({ success: true, message: 'Прайс-лист успешно загружен' });
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Ошибка загрузки прайс-листа:', error);
        res.status(500).json({ error: 'Ошибка сервера при загрузке прайс-листа' });
    }
});

// Добавление товара вручную
app.post('/api/products', async (req, res) => {
    const { article, name, unit, price, brand, group, username } = req.body;

    if (!username || !article || !name || !unit || !price || !brand) {
        return res.status(400).json({
            error: 'Не все обязательные поля заполнены'
        });
    }

    try {
        const [users] = await db.execute('SELECT role FROM users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        const userRole = users[0].role;
        if (!['admin', 'user'].includes(userRole)) {
            return res.status(403).json({ error: 'Недостаточно прав для добавления товаров' });
        }

        const [existing] = await db.execute(
            'SELECT id FROM price_list WHERE article = ? AND brand = ?',
            [article, brand]
        );

        if (existing.length > 0) {
            return res.status(400).json({
                error: 'Товар с таким артикулом и брендом уже существует'
            });
        }

        await db.execute(
            'INSERT INTO price_list (article, name, unit, price, brand, `group`, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [article, name, unit, parseFloat(price), brand, group || null, username]
        );

        console.log(`✅ Товар добавлен: ${article} (${brand}) пользователем ${username}`);
        res.json({ success: true, message: 'Товар успешно добавлен' });

    } catch (error) {
        console.error('❌ Ошибка при добавлении товара:', error);
        res.status(500).json({ error: 'Ошибка сервера при добавлении товара' });
    }
});

// Редактирование товара
app.put('/api/products/:article', async (req, res) => {
    const { article } = req.params;
    const { name, unit, price, brand, group, username, originalBrand } = req.body;

    if (!username || !name || !unit || !price || !brand) {
        return res.status(400).json({ error: 'Не все обязательные поля заполнены' });
    }

    try {
        const [users] = await db.execute('SELECT role FROM users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        const userRole = users[0].role;
        if (!['admin', 'user'].includes(userRole)) {
            return res.status(403).json({ error: 'Недостаточно прав для редактирования товаров' });
        }

        // Используем originalBrand для поиска, если передан
        const searchBrand = originalBrand || brand;
        const [existing] = await db.execute(
            'SELECT id FROM price_list WHERE article = ? AND brand = ?',
            [article, searchBrand]
        );
        
        if (existing.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }

        // Проверяем, не конфликтует ли новый артикул+бренд с другим товаром
        if (article !== req.params.article || brand !== searchBrand) {
            const [conflict] = await db.execute(
                'SELECT id FROM price_list WHERE article = ? AND brand = ? AND id != ?',
                [article, brand, existing[0].id]
            );
            
            if (conflict.length > 0) {
                return res.status(400).json({ error: 'Товар с таким артикулом и брендом уже существует' });
            }
        }

        await db.execute(
            'UPDATE price_list SET article = ?, name = ?, unit = ?, price = ?, brand = ?, `group` = ? WHERE id = ?',
            [article, name, unit, parseFloat(price), brand, group || null, existing[0].id]
        );

        console.log(`✅ Товар обновлён: ${article} (${brand}) пользователем ${username}`);
        res.json({ success: true, message: 'Товар успешно обновлён' });

    } catch (error) {
        console.error('❌ Ошибка при обновлении товара:', error);
        res.status(500).json({ error: 'Ошибка сервера при обновлении товара' });
    }
});

// Удаление товара
app.delete('/api/products/:article', async (req, res) => {
    const { article } = req.params;
    const { brand, username } = req.body;

    if (!username || !brand) {
        return res.status(400).json({ error: 'Необходимы артикул, бренд и имя пользователя' });
    }

    try {
        const [users] = await db.execute('SELECT role FROM users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        const userRole = users[0].role;
        if (userRole !== 'admin') {
            return res.status(403).json({ error: 'Недостаточно прав для удаления товаров' });
        }

        const [result] = await db.execute(
            'DELETE FROM price_list WHERE article = ? AND brand = ?',
            [article, brand]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }

        console.log(`✅ Товар удалён: ${article} (${brand}) пользователем ${username}`);
        res.json({ success: true, message: 'Товар успешно удалён' });

    } catch (error) {
        console.error('❌ Ошибка при удалении товара:', error);
        res.status(500).json({ error: 'Ошибка сервера при удалении товара' });
    }
});

// Получение заказов
app.get('/api/orders', async (req, res) => {
    const username = req.query.username;

    try {
        let query = `
            SELECT o.* 
            FROM orders o 
        `;
        const params = [];

        if (username && username !== 'admin') {
            query += ' WHERE o.user = ?';
            params.push(username);
        }

        query += ' ORDER BY o.created_at DESC';

        const [ordersRows] = await db.execute(query, params);

        const orders = [];

        for (const orderRow of ordersRows) {
            const [subordersRows] = await db.execute('SELECT * FROM suborders WHERE order_id = ?', [orderRow.id]);
            const suborders = [];

            for (const suborderRow of subordersRows) {
                const [itemsRows] = await db.execute('SELECT * FROM order_items WHERE suborder_id = ?', [suborderRow.id]);
                suborders.push({
                    id: suborderRow.id,
                    name: suborderRow.name,
                    total: parseFloat(suborderRow.total),
                    positions: itemsRows.map(item => ({
                        article: item.article,
                        name: item.name,
                        brand: item.brand,
                        unit: item.unit,
                        price: parseFloat(item.price),
                        quantity: item.quantity,
                        total: parseFloat(item.total)
                    }))
                });
            }

            // Получаем наценки на бренды для этого заказа
            const [markupsRows] = await db.execute('SELECT * FROM order_brand_markups WHERE order_id = ?', [orderRow.id]);
            const brandMarkups = {};
            markupsRows.forEach(row => {
                brandMarkups[row.brand] = parseFloat(row.markup);
            });

            orders.push({
                number: orderRow.number,
                date: orderRow.date.toISOString().split('T')[0],
                user: orderRow.user,
                comment: orderRow.comment,
                total: parseFloat(orderRow.total),
                discount: parseFloat(orderRow.discount),
                suborders: suborders,
                brandMarkups: brandMarkups
            });
        }

        res.json(orders);
    } catch (error) {
        console.error('Ошибка получения заказов:', error);
        res.status(500).json({ error: 'Ошибка сервера при получении заказов' });
    }
});

// Сохранение заказа
app.post('/api/orders', async (req, res) => {
    const order = req.body;
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        // Проверяем существование заказа
        const [existingOrders] = await connection.execute('SELECT id FROM orders WHERE number = ?', [order.number]);
        let orderId;

        if (existingOrders.length > 0) {
            // Обновляем существующий заказ
            orderId = existingOrders[0].id;
            
            // Удаляем старые данные
            await connection.execute('DELETE FROM order_brand_markups WHERE order_id = ?', [orderId]);
            
            const [suborders] = await connection.execute('SELECT id FROM suborders WHERE order_id = ?', [orderId]);
            for (const suborder of suborders) {
                await connection.execute('DELETE FROM order_items WHERE suborder_id = ?', [suborder.id]);
            }
            await connection.execute('DELETE FROM suborders WHERE order_id = ?', [orderId]);
            
            // Обновляем заказ
            await connection.execute(
                'UPDATE orders SET date = ?, user = ?, comment = ?, total = ?, discount = ? WHERE id = ?',
                [order.date, order.user, order.comment || '', order.total || 0, order.discount || 0, orderId]
            );
        } else {
            // Создаем новый заказ
            const [orderResult] = await connection.execute(
                'INSERT INTO orders (number, date, user, comment, total, discount) VALUES (?, ?, ?, ?, ?, ?)',
                [order.number, order.date, order.user, order.comment || '', order.total || 0, order.discount || 0]
            );
            orderId = orderResult.insertId;
        }

        // Сохраняем подзаказы и позиции
        for (const suborder of order.suborders || []) {
            const [suborderResult] = await connection.execute(
                'INSERT INTO suborders (order_id, name, total) VALUES (?, ?, ?)',
                [orderId, suborder.name || '', suborder.total || 0]
            );

            const suborderId = suborderResult.insertId;

            for (const position of suborder.positions || []) {
                await connection.execute(
                    'INSERT INTO order_items (suborder_id, article, name, brand, unit, price, quantity, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    [suborderId, position.article || '', position.name || '', position.brand || '', 
                     position.unit || '', position.price || 0, position.quantity || 0, position.total || 0]
                );
            }
        }

        // Сохраняем наценки на бренды
        if (order.brandMarkups) {
            for (const [brand, markup] of Object.entries(order.brandMarkups)) {
                await connection.execute(
                    'INSERT INTO order_brand_markups (order_id, brand, markup) VALUES (?, ?, ?)',
                    [orderId, brand, markup]
                );
            }
        }

        await connection.commit();
        res.json({ success: true, message: 'Заказ успешно сохранён' });
    } catch (error) {
        await connection.rollback();
        console.error('Ошибка сохранения заказа:', error);
        res.status(500).json({ error: 'Ошибка сервера при сохранении заказа' });
    } finally {
        connection.release();
    }
});

// Копирование заказа
app.post('/api/orders/:orderNumber/copy', async (req, res) => {
    const orderNumber = req.params.orderNumber;
    const { newNumber, username } = req.body;

    if (!username) {
        return res.status(401).json({ error: 'Необходима авторизация' });
    }

    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        // Находим исходный заказ
        const [orders] = await connection.execute('SELECT * FROM orders WHERE number = ?', [orderNumber]);
        if (orders.length === 0) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }

        const originalOrder = orders[0];

        // Создаем новый заказ
        const [orderResult] = await connection.execute(
            'INSERT INTO orders (number, date, user, comment, total, discount) VALUES (?, ?, ?, ?, ?, ?)',
            [newNumber, new Date().toISOString().split('T')[0], username, originalOrder.comment, 0, originalOrder.discount]
        );

        const newOrderId = orderResult.insertId;

        // Копируем подзаказы и позиции
        const [suborders] = await connection.execute('SELECT * FROM suborders WHERE order_id = ?', [originalOrder.id]);
        
        for (const suborder of suborders) {
            const [suborderResult] = await connection.execute(
                'INSERT INTO suborders (order_id, name, total) VALUES (?, ?, ?)',
                [newOrderId, suborder.name, 0]
            );

            const newSuborderId = suborderResult.insertId;

            const [items] = await connection.execute('SELECT * FROM order_items WHERE suborder_id = ?', [suborder.id]);
            
            let suborderTotal = 0;
            for (const item of items) {
                const itemTotal = item.price * item.quantity;
                suborderTotal += itemTotal;
                
                await connection.execute(
                    'INSERT INTO order_items (suborder_id, article, name, brand, unit, price, quantity, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    [newSuborderId, item.article, item.name, item.brand, item.unit, item.price, item.quantity, itemTotal]
                );
            }

            // Обновляем итог подзаказа
            await connection.execute(
                'UPDATE suborders SET total = ? WHERE id = ?',
                [suborderTotal, newSuborderId]
            );
        }

        // Копируем наценки на бренды
        const [markups] = await connection.execute('SELECT * FROM order_brand_markups WHERE order_id = ?', [originalOrder.id]);
        for (const markup of markups) {
            await connection.execute(
                'INSERT INTO order_brand_markups (order_id, brand, markup) VALUES (?, ?, ?)',
                [newOrderId, markup.brand, markup.markup]
            );
        }

        // Обновляем общий итог заказа
        const [newSuborders] = await connection.execute('SELECT SUM(total) as total FROM suborders WHERE order_id = ?', [newOrderId]);
        const newTotal = newSuborders[0].total || 0;
        
        await connection.execute(
            'UPDATE orders SET total = ? WHERE id = ?',
            [newTotal, newOrderId]
        );

        await connection.commit();
        res.json({ success: true, message: 'Заказ успешно скопирован', newOrderNumber: newNumber });
    } catch (error) {
        await connection.rollback();
        console.error('Ошибка копирования заказа:', error);
        res.status(500).json({ error: 'Ошибка сервера при копировании заказа' });
    } finally {
        connection.release();
    }
});

// Экспорт заказа в Excel
app.get('/api/orders/:orderNumber/export', async (req, res) => {
    const orderNumber = req.params.orderNumber;

    try {
        const [orders] = await db.execute('SELECT * FROM orders WHERE number = ?', [orderNumber]);
        if (orders.length === 0) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }

        const order = orders[0];
        const [suborders] = await db.execute('SELECT * FROM suborders WHERE order_id = ?', [order.id]);

        // Собираем все позиции заказа
        let allPositions = [];
        for (const suborder of suborders) {
            const [items] = await db.execute('SELECT * FROM order_items WHERE suborder_id = ?', [suborder.id]);
            allPositions = allPositions.concat(items.map(item => ({
                'Подзаказ': suborder.name,
                'Артикул': item.article,
                'Наименование': item.name,
                'Бренд': item.brand,
                'Ед. изм.': item.unit,
                'Цена за ед.': item.price,
                'Количество': item.quantity,
                'Сумма': item.total
            })));
        }

        // Получаем наценки на бренды
        const [markups] = await db.execute('SELECT * FROM order_brand_markups WHERE order_id = ?', [order.id]);
        const brandMarkups = {};
        markups.forEach(markup => {
            brandMarkups[markup.brand] = markup.markup;
        });

        // Создаем книгу Excel
        const workbook = XLSX.utils.book_new();
        
        // Лист с позициями
        const positionsSheet = XLSX.utils.json_to_sheet(allPositions);
        XLSX.utils.book_append_sheet(workbook, positionsSheet, 'Позиции заказа');
        
        // Лист с информацией о заказе
        const orderInfo = [
            ['Номер заказа:', order.number],
            ['Дата заказа:', order.date],
            ['Пользователь:', order.user],
            ['Комментарий:', order.comment],
            ['Общая сумма:', order.total],
            ['Скидка на заказ:', order.discount + '%'],
            [''],
            ['Наценки по брендам:']
        ];

        Object.entries(brandMarkups).forEach(([brand, markup]) => {
            orderInfo.push([brand, markup + '%']);
        });

        const infoSheet = XLSX.utils.aoa_to_sheet(orderInfo);
        XLSX.utils.book_append_sheet(workbook, infoSheet, 'Информация о заказе');

        // Генерируем файл
        const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename=заказ_${order.number}.xlsx`);
        res.send(excelBuffer);

    } catch (error) {
        console.error('Ошибка экспорта заказа:', error);
        res.status(500).json({ error: 'Ошибка сервера при экспорте заказа' });
    }
});

// Удаление заказа
app.delete('/api/orders/:orderNumber', async (req, res) => {
    const orderNumber = req.params.orderNumber;
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();
        const [orders] = await connection.execute('SELECT id FROM orders WHERE number = ?', [orderNumber]);

        if (orders.length === 0) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }

        const orderId = orders[0].id;
        await connection.execute('DELETE FROM order_brand_markups WHERE order_id = ?', [orderId]);
        
        const [suborders] = await connection.execute('SELECT id FROM suborders WHERE order_id = ?', [orderId]);
        for (const suborder of suborders) {
            await connection.execute('DELETE FROM order_items WHERE suborder_id = ?', [suborder.id]);
        }
        
        await connection.execute('DELETE FROM suborders WHERE order_id = ?', [orderId]);
        await connection.execute('DELETE FROM orders WHERE id = ?', [orderId]);

        await connection.commit();
        res.json({ success: true, message: 'Заказ успешно удалён' });
    } catch (error) {
        await connection.rollback();
        console.error('Ошибка удаления заказа:', error);
        res.status(500).json({ error: 'Ошибка сервера при удалении заказа' });
    } finally {
        connection.release();
    }
});

// Получение пользователей
app.get('/api/users', async (req, res) => {
    try {
        const [users] = await db.execute('SELECT username, role, can_upload_price FROM users');
        const result = users.map(user => ({
            username: user.username,
            role: user.role,
            canUploadPrice: user.can_upload_price === 1
        }));
        res.json(result);
    } catch (error) {
        console.error('Ошибка получения пользователей:', error);
        res.status(500).json({ error: 'Ошибка сервера при получении пользователей' });
    }
});

// Добавление пользователя
app.post('/api/users', async (req, res) => {
    const { username, password, role, canUploadPrice } = req.body;

    if (!['admin', 'user', 'viewer'].includes(role)) {
        return res.status(400).json({ error: 'Некорректная роль' });
    }

    try {
        // Проверяем, существует ли пользователь
        const [existing] = await db.execute('SELECT id FROM users WHERE username = ?', [username]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO users (username, password, role, can_upload_price) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, canUploadPrice ? 1 : 0]
        );

        res.json({ success: true, message: 'Пользователь успешно добавлен' });
    } catch (error) {
        console.error('Ошибка добавления пользователя:', error);
        res.status(500).json({ error: 'Ошибка сервера при добавлении пользователя' });
    }
});

// Обновление пользователя
app.put('/api/users/:username', async (req, res) => {
    const username = req.params.username;
    const { role, canUploadPrice, password } = req.body;

    try {
        let query = 'UPDATE users SET role = ?, can_upload_price = ?';
        const params = [role, canUploadPrice ? 1 : 0];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', password = ?';
            params.push(hashedPassword);
        }

        query += ' WHERE username = ?';
        params.push(username);

        const [result] = await db.execute(query, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        res.json({ success: true, message: 'Пользователь успешно обновлён' });
    } catch (error) {
        console.error('Ошибка обновления пользователя:', error);
        res.status(500).json({ error: 'Ошибка сервера при обновлении пользователя' });
    }
});

// Удаление пользователя
app.delete('/api/users/:username', async (req, res) => {
    const username = req.params.username;

    try {
        // Не позволяем удалить самого себя
        if (req.body.currentUser === username) {
            return res.status(400).json({ error: 'Нельзя удалить текущего пользователя' });
        }

        const [result] = await db.execute('DELETE FROM users WHERE username = ?', [username]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        res.json({ success: true, message: 'Пользователь успешно удалён' });
    } catch (error) {
        console.error('Ошибка удаления пользователя:', error);
        res.status(500).json({ error: 'Ошибка сервера при удалении пользователя' });
    }
});

// Получение глобальных наценок
app.get('/api/brand-markups', async (req, res) => {
    try {
        const [markups] = await db.execute('SELECT brand, markup FROM global_brand_markups');
        const result = {};
        markups.forEach(row => {
            result[row.brand] = row.markup;
        });
        res.json(result);
    } catch (error) {
        console.error('Ошибка получения наценок:', error);
        res.status(500).json({ error: 'Ошибка сервера при получении наценок' });
    }
});

// Сохранение глобальных наценок
app.post('/api/brand-markups', async (req, res) => {
    const { brand, markup } = req.body;

    try {
        await db.execute(
            'INSERT INTO global_brand_markups (brand, markup) VALUES (?, ?) ON DUPLICATE KEY UPDATE markup = VALUES(markup)',
            [brand, markup]
        );

        res.json({ success: true, message: 'Наценка успешно сохранена' });
    } catch (error) {
        console.error('Ошибка сохранения наценки:', error);
        res.status(500).json({ error: 'Ошибка сервера при сохранении наценки' });
    }
});

// Поиск товаров
app.get('/api/products/search', async (req, res) => {
    const { q } = req.query;

    if (!q || q.length < 2) {
        return res.json([]);
    }

    try {
        const searchTerm = `%${q}%`;
        const [products] = await db.execute(
            'SELECT * FROM price_list WHERE article LIKE ? OR name LIKE ? OR brand LIKE ? LIMIT 20',
            [searchTerm, searchTerm, searchTerm]
        );

        const result = products.map(product => ({
            article: product.article,
            name: product.name,
            unit: product.unit,
            price: product.price,
            brand: product.brand,
            group: product.group
        }));

        res.json(result);
    } catch (error) {
        console.error('Ошибка поиска товаров:', error);
        res.status(500).json({ error: 'Ошибка сервера при поиске товаров' });
    }
});

// Получение товара по артикулу и бренду
app.get('/api/products/:article', async (req, res) => {
    const { article } = req.params;
    const { brand } = req.query;

    try {
        let query = 'SELECT * FROM price_list WHERE article = ?';
        const params = [article];

        if (brand) {
            query += ' AND brand = ?';
            params.push(brand);
        }

        const [products] = await db.execute(query, params);

        if (products.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }

        const product = products[0];
        res.json({
            article: product.article,
            name: product.name,
            unit: product.unit,
            price: product.price,
            brand: product.brand,
            group: product.group
        });
    } catch (error) {
        console.error('Ошибка получения товара:', error);
        res.status(500).json({ error: 'Ошибка сервера при получении товара' });
    }
});

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Сервер запущен на http://localhost:${PORT}`);
});