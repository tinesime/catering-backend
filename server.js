const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const cors = require('cors')
const moment = require('moment')
const dotenv = require('dotenv')
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const multer = require("multer")
const XLSX = require("xlsx")

dotenv.config()

const jwtSecret = process.env.JWT_SECRET
const blacklist = []

const app = express()

app.use(bodyParser.json())

const corsOptions = {
    origin: 'http://localhost:5173',
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions))

app.use(cookieParser())

const PORT = process.env.PORT || 8000

const storage = multer.memoryStorage()
const upload = multer({storage: storage})

const itemSchema = new mongoose.Schema({
    date: Date, menu: String, type: String, name: String, allergens: [String],
})

const userSchema = new mongoose.Schema({
    username: {type: String, unique: true, required: true},
    password: {type: String, required: true},
    role: {type: String, default: 'Mitarbeiter'}
})

const menuSchema = new mongoose.Schema({
    date: {type: Date, required: true},
    menuNumber: {type: Number, required: true},
    items: {type: [itemSchema]},
})

const orderedSchema = new mongoose.Schema({
    userId: {type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true},
    menuId: {type: mongoose.Schema.Types.ObjectId, ref: 'Menu', required: true},
    orderDate: {type: Date, default: Date.now}
})

const Item = mongoose.model('Item', itemSchema)
const User = mongoose.model('User', userSchema)
const Menu = mongoose.model('Menu', menuSchema)
const Ordered = mongoose.model('Ordered', orderedSchema)

const authenticate = async (req, res, next) => {
    const authHeader = req.header('Authorization')
    if (!authHeader) {
        return res.status(401).send('Unauthorized')
    }

    const token = authHeader.replace('Bearer ', '')
    if (!token || blacklist.includes(token)) {
        return res.status(401).send('Unauthorized')
    }

    try {
        const decoded = jwt.verify(token, jwtSecret)
        const user = await User.findById(decoded.userId)
        if (!user) {
            return res.status(403).send('Forbidden')
        }

        req.user = user
        next()
    } catch (error) {
        res.status(401).send('Invalid token')
    }
}

app.get('/api/menu/:menuId', async (req, res) => {
    try {
        const menuId = req.params.menuId
        const items = await Menu.findById({_id: menuId});
        res.status(200).send(items);
    } catch (error) {
        res.status(500).send("Das Menü konnte nicht gefunden werden");
    }
})

app.get('/api/ordered/:menuId/:date', authenticate, async (req, res) => {
    try {
        const menuId = req.params.menuId
        const userId = req.user._id
        const date = req.params.date
        const orders = await Ordered.find({userId: userId, menuId: menuId, orderDate: {$eq: date}})
        return res.status(200).json({ordered: orders.length > 0})
    } catch (error) {
        res.status(500).send('Error fetching orders')
    }
})

app.get('/api/menu/:from/:to', authenticate, async (req, res) => {
    try {
        const from = moment.utc(req.params.from, 'YYYY-MM-DD').startOf('day').toDate()
        const to = moment.utc(req.params.to, 'YYYY-MM-DD').startOf('day').toDate()
        const menus = await Menu.find({date: {$gte: from, $lte: to}})
        res.status(200).send(menus)
    } catch (error) {
        res.status(500).send('Error fetching menus')
    }
})

app.post('/api/register', async (req, res) => {
    try {
        const {username, password, role} = req.body
        const hashedPassword = await bcrypt.hash(password, 10)
        const user = new User({username, password: hashedPassword, role})
        await user.save()
        res.status(201).send('User registered successfully')
    } catch (error) {
        res.status(500).send('Error registering user')
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const {username, password} = req.body
        const user = await User.findOne({username: username})
        if (!user) {
            return res.status(400).json({error: 'User not found'})
        }

        const validPassword = bcrypt.compare(password, user.password)
        if (!validPassword) {
            return res.status(400).json({error: 'Invalid password'})
        }

        const token = jwt.sign({
            userId: user._id, username: user.username, role: user.role
        }, jwtSecret, {expiresIn: '20m'})

        await res.send({token, user})
    } catch (error) {
        await res.status(500).send('Error logging in')
    }
})

app.post('/api/logout', authenticate, async (req, res) => {
    const token = await req.header('Authorization').replace('Bearer ', '')
    blacklist.push(token)
    await res.status(200).send('User logged out successfully')
})

app.post('/api/upload', authenticate, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('Keine Datei hochgeladen')
        }

        const workbook = XLSX.read(req.file.buffer)
        const sheetName = workbook.SheetNames[0]
        const worksheet = workbook.Sheets[sheetName]
        const json = XLSX.utils.sheet_to_json(worksheet, {header: 1})

        const defaultMenus = ['Menü 1', 'Menü 3', 'Menü 2']
        const defaultTypes = ['Suppe', 'Hauptspeise', 'Salat', 'Desert']
        const defaultAllergens = ['Gluten', 'Krebstiere', 'Eier', 'Fisch', 'Erdnüsse', 'Soja', 'Milch', 'Schalenfrüchte', 'Sellerie', 'Senf', 'Sesam', 'Schwefeldioxid und Sulphite', 'Lupinen', 'Weichtiere']

        const items = json.slice(1).flatMap(row => {
            const date = new Date(Math.round((row[0] - 25569) * 86400 * 1000))
            if (isNaN(date.getTime())) {
                return null;
            }

            let menus = []
            for (let i = 0; i < defaultMenus.length; i++) {
                if (row[i + 1] === 1) {
                    menus.push(defaultMenus[i])
                }
            }

            let type = ''
            for (let i = 0; i < defaultTypes.length; i++) {
                if (row[i + 4] === 1) {
                    type = defaultTypes[i]
                }
            }

            const name = row[8]

            let allergens = []
            for (let i = 0; i < defaultAllergens.length; i++) {
                if (row[i + 9] === 1) {
                    allergens.push(defaultAllergens[i])
                }
            }


            return menus.map(menu => ({
                date, menu, type, name, allergens
            }))
        }).filter(item => item !== null)

        await Item.insertMany(items)

        const dailyMenu = {}

        items.forEach(item => {
            if (!dailyMenu[item.menu]) {
                dailyMenu[item.menu] = {}
            }

            const dateStr = moment.utc(item.date).format('YYYY-MM-DD')
            if (!dailyMenu[item.menu][dateStr]) {
                dailyMenu[item.menu][dateStr] = []
            }

            dailyMenu[item.menu][dateStr].push(item)
        })

        for (const [menu, dates] of Object.entries(dailyMenu)) {
            for (const [date, items] of Object.entries(dates)) {
                let menuNumber = parseInt(menu.match(/\d+/)[0], 10)
                await Menu.create({
                    date: new Date(date), menuNumber: menuNumber, items: items
                })
            }
        }

        res.status(200).send('File uploaded and data inserted successfully')
    } catch (error) {
        res.status(500).send('Error processing file')
    }
})

app.post('/api/order/:menuId', authenticate, async (req, res) => {
    try {
        const menuId = req.params.menuId
        const userId = req.user._id
        const date = moment.utc().startOf('day').toDate()

        const existingOrder = await Ordered.findOne({userId: userId, menuId: menuId, orderDate: date})
        if (existingOrder) {
            return res.status(400).send('Menü bereits bestellt')
        }

        const newOrder = new Ordered({
            userId: userId, menuId: menuId, orderDate: date
        })

        await newOrder.save()
        res.status(200).send('Menü erfolgreich bestellt')
    } catch (error) {
        res.status(500).send('Menü konnte nicht bestellt werden');
    }
})

app.delete('/api/cancel/:orderId', authenticate, async (req, res) => {
    try {
        await Ordered.deleteOne({_id: req.params.orderId})
        res.status(200).send('Bestellung erfolgreich storniert')
    } catch (error) {
        res.status(500).send('Bestellung konnte nicht storniert werden')
    }
})

app.get('/api/ordered', authenticate, async (req, res) => {
    try {
        const userId = req.user._id
        const orders = await Ordered.find({userId: userId})
        res.status(200).send(orders)
    } catch (error) {
        res.status(500).send('Error fetching orders')
    }
})

mongoose.connect('mongodb://localhost:27017/catering')
    .then(() => app.listen(PORT, () => console.log('Server running on port 8000')))
    .catch(err => console.error(err));