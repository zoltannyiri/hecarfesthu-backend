import express, { Application, NextFunction, Request, Response } from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import multer, { FileFilterCallback } from "multer";
import { v4 as uuidv4 } from 'uuid';
import { Readable } from "stream";
import { google as googleApis } from 'googleapis'; // Módosított név
import nodemailer from 'nodemailer';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Környezeti változók betöltése
dotenv.config({
    path: path.join(__dirname, "/.env"),
});

const app: Application = express();
const PORT: number = 3000;

// Middleware
app.use(express.json());
app.use(cors());


//ADMIN LOGOLÁS
// Audit log séma
const auditLogSchema = new mongoose.Schema({
    action: { type: String, required: true }, // pl. 'login', 'status_change', 'email_sent'
    adminUser: { type: String, required: true },
    targetId: { type: mongoose.Schema.Types.ObjectId }, // érintett regisztráció ID
    targetType: { type: String }, // pl. 'registration'
    changes: { type: Object }, // változtatások részletei
    ipAddress: { type: String },
    userAgent: { type: String },
    timestamp: { type: Date, default: Date.now }
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);


async function logAction(req: Request, action: string, details: any = {}) {
    try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];
        
        // Ha van targetId, lekérjük a regisztrációt
        let registrationDetails = {};
        if (details.targetId) {
            const reg = await VIPRegistration.findById(details.targetId);
            if (reg) {
                registrationDetails = {
                    regName: `${reg.firstName} ${reg.lastName}`,
                    regEmail: reg.email,
                    regLicensePlate: reg.licensePlate,
                    regCarType: reg.carType
                };
            }
        }

        // Egyesítjük a manuálisan megadott változtatásokat és a regisztrációs adatokat
        const finalChanges = {
            ...(details.changes || {}),
            ...registrationDetails
        };

        await new AuditLog({
            action,
            adminUser: (req as any).user?.username || 'unknown',
            targetId: details.targetId,
            targetType: details.targetType,
            changes: finalChanges,
            ipAddress: ip,
            userAgent: userAgent
        }).save();
    } catch (error) {
        console.error('Hiba a naplózás során:', error);
    }
}

// app.get('/api/admin/audit-logs', authenticateToken, async (req: Request, res: Response) => {
//     try {
//         const { limit = 100, page = 1 } = req.query;
//         const logs = await AuditLog.find()
//             .sort({ timestamp: -1 })
//             .limit(Number(limit))
//             .skip((Number(page) - 1) * Number(limit));
            
//         res.json(logs);
//     } catch (error) {
//         console.error('Hiba a naplók lekérdezésekor:', error);
//         res.status(500).json({ message: 'Hiba történt a naplók lekérdezése során' });
//     }
// });

// Audit log végpont a server.ts-ben
app.get('/api/admin/audit-logs', authenticateToken, async (req: Request, res: Response) => {
    try {
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
        res.json(logs);
    } catch (error) {
        console.error('Hiba a naplók lekérdezésekor:', error);
        res.status(500).json({ message: 'Hiba történt a naplók lekérdezése során' });
    }
});



// OAuth2 konfiguráció
const oauth2Client = new googleApis.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    'https://developers.google.com/oauthplayground'
);

oauth2Client.setCredentials({
    refresh_token: process.env.GMAIL_REFRESH_TOKEN
});

// Gmail API inicializálása
const gmail = googleApis.gmail({ version: 'v1', auth: oauth2Client });

// Email küldése Gmail API-val
async function sendEmail(to: string, subject: string, html: string) {
    try {
        const utf8Subject = `=?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`;
        const utf8FromName = `=?UTF-8?B?${Buffer.from('HéCarFest').toString('base64')}?=`;
        
        const messageParts = [
            `From: ${utf8FromName} <${process.env.GMAIL_USER}>`,
            `To: ${to}`,
            'Content-Type: text/html; charset=UTF-8',
            'MIME-Version: 1.0',
            `Subject: ${utf8Subject}`,
            '',
            html
        ];
        
        const message = messageParts.join('\n');
        const encodedMessage = Buffer.from(message)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, ''); 

        const res = await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: encodedMessage
            }
        });
        
        console.log('Email elküldve:', res.data.id);
        return res.data;
        
    } catch (error) {
        console.error('Hiba email küldéskor:', error);
        throw error;
    }
}



// Email küldés admin felületről
app.post('/api/admin/send-email', authenticateToken, async (req: Request, res: Response) => {
    try {
        const { registrationId, to, subject, message, notificationType } = req.body;

        await sendEmail(to, subject, message);

        await VIPRegistration.findByIdAndUpdate(
            registrationId,
            { $push: { notifications: { notificationType, message: subject } }}
        );

        await logAction(req, 'email_sent', {
            targetId: registrationId, // Ez biztosítja, hogy a regisztráció adatai betöltődjenek
            targetType: 'registration',
            changes: {
                to,
                subject
            }
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Hiba email küldéskor:', error);
        res.status(500).json({ success: false, message: 'Hiba történt az email küldése során' });
    }
});







// Értesítési állapot módosítása
app.put('/api/admin/registrations/:id/notified', authenticateToken, async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const { notified } = req.body;

        await logAction(req, 'notification_toggled', {
            targetId: id,
            targetType: 'registration',
            changes: {
                notified
            }
        });
        
        const updatedReg = await VIPRegistration.findByIdAndUpdate(
            id, 
            { notified },
            { new: true }
        );

        if (!updatedReg) {
            return res.status(404).json({ message: 'Regisztráció nem található' });
        }

        res.json(updatedReg);
    } catch (error) {
        console.error('Értesítési állapot módosítási hiba:', error);
        res.status(500).json({ message: 'Hiba történt az értesítési állapot módosítása során' });
    }
});



// Multer konfiguráció
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|webp/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (mimetype && extname) cb(null, true);
        else cb(new Error('Csak képek (jpeg, jpg, png, webp) engedélyezettek!'));
    }
});

// MongoDB kapcsolat
mongoose.connect(process.env.MONGODB_URL as string, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
} as mongoose.ConnectOptions)
    .then(() => {
        console.log("Csatlakozva a MongoDB-hez!");
        // setTimeout(() => createInitialAdmin(), 1000); //ezt majd TÖRÖLD HA MEGVANNAK AZ ADMIN FELHASZNÁLÓK, 600. sor
    })
    .catch((err: Error) => {
        console.error("MongoDB kapcsolati hiba:", err);
    });

// Google Drive konfiguráció
const KEYFILEPATH = 'C:\\hecarfest.hu\\hecarfest.hu\\api\\src\\hecarfest-vip-1c7e3c451f3f.json';
const authDrive = new googleApis.auth.GoogleAuth({
    keyFile: KEYFILEPATH,
    scopes: ['https://www.googleapis.com/auth/drive']
});

const drive = googleApis.drive({ version: 'v3', auth: authDrive });

// Segédfüggvény a Google Drive-ba feltöltéshez
// Módosítsd az uploadToDrive függvényt
async function uploadToDrive(file: Express.Multer.File): Promise<string> {
    try {
        const fileMetadata = {
            name: `${Date.now()}_${file.originalname}`,
            parents: ["1VVxhZ0BMwck3V_3kNktawQRt4puASq6X"],
        };

        const media = {
            mimeType: file.mimetype,
            body: Readable.from(file.buffer),
        };

        const response = await drive.files.create({
            requestBody: fileMetadata,
            media: media,
            fields: 'id',
        });

        await drive.permissions.create({
            fileId: response.data.id!,
            requestBody: {
                role: 'reader',
                type: 'anyone',
            },
        });

        // Egységes URL formátum, méret paraméterrel, de authuser nélkül
        return `https://lh3.googleusercontent.com/d/${response.data.id}=s400`;
        
    } catch (error) {
        console.error('HIBA a Drive feltöltésnél:', error);
        throw new Error(`Drive feltöltés sikertelen: ${(error as Error).message}`);
    }
}


// VIP Regisztrációs séma
const vipRegistrationSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    licensePlate: { type: String, required: true },
    carType: { type: String, required: true },
    carImages: [{ type: String }],
    interiorImage: { type: String },
    carStory: { type: String, required: true },
    privacyAccepted: { type: Boolean, required: true },
    registrationDate: { type: Date, default: Date.now },
    status: { 
        type: String, 
        enum: ['pending', 'accepted', 'rejected', 'maybe'], 
        default: 'pending' 
    },
    notified: { type: Boolean, default: false },
});

const VIPRegistration = mongoose.model('VIPRegistration', vipRegistrationSchema);

// VIP regisztrációs végpont
app.post('/api/vip-registration',
    upload.fields([
        { name: 'carImage1', maxCount: 1 },
        { name: 'carImage2', maxCount: 1 },
        { name: 'carImage3', maxCount: 1 },
        { name: 'carImage4', maxCount: 1 },
        { name: 'interiorImage', maxCount: 1 }
    ]),
    async (req: Request, res: Response) => {
        try {
            const {
                firstname,
                lastname,
                email,
                phone,
                licenseplate,
                cartype,
                notes,
                privacy
            } = req.body;

            if (!firstname || !lastname || !email || !phone || !licenseplate || !cartype || !notes || !privacy) {
                return res.status(400).json({
                    success: false,
                    message: 'Minden kötelező mezőt ki kell tölteni!'
                });
            }

            const files = req.files as { [fieldname: string]: Express.Multer.File[] };
            const carImages = [];
            const imageFields = ['carImage1', 'carImage2', 'carImage3', 'carImage4'];
            
            for (const field of imageFields) {
                if (files[field] && files[field][0]) {
                    try {
                        const fileUrl = await uploadToDrive(files[field][0]);
                        carImages.push(fileUrl);
                    } catch (uploadError) {
                        console.error('Hiba a feltöltés során:', uploadError);
                        throw uploadError;
                    }
                }
            }

            let interiorImage = '';
            if (files['interiorImage'] && files['interiorImage'][0]) {
                interiorImage = await uploadToDrive(files['interiorImage'][0]);
            }

            const newRegistration = new VIPRegistration({
                firstName: firstname,
                lastName: lastname,
                email,
                phone,
                licensePlate: licenseplate,
                carType: cartype,
                carImages,
                interiorImage,
                carStory: notes,
                privacyAccepted: privacy === 'on'
            });

            await newRegistration.save();

            // Email küldése Gmail API-val
            try {
                await sendEmail(
                    email,
                    'Köszönjük regisztrációdat!',
                    `
                        <h1>Köszönjük, hogy regisztráltál a HéCarFest VIP szektorba!</h1>
                        <p>Kedves ${firstname} ${lastname},</p>
                        <p>Megkaptuk regisztrációd, hamarosan értesítünk a további információkról.</p>
                        <p><strong>Regisztrációs adataid:</strong></p>
                        <ul>
                            <li>Név: ${firstname} ${lastname}</li>
                            <li>Email: ${email}</li>
                            <li>Rendszám: ${licenseplate}</li>
                            <li>Autó típusa: ${cartype}</li>
                        </ul>
                        <p>Üdvözlettel,<br>HéCarFest csapata</p>
                    `
                );
                console.log(`Visszaigazoló email elküldve: ${email}`);
            } catch (emailError) {
                console.error('Hiba email küldéskor:', emailError);
            }

            res.status(201).json({
                success: true,
                message: 'Sikeres regisztráció! Hamarosan értesítünk e-mailben.'
            });
        } catch (error) {
            console.error('Regisztrációs hiba:', error);
            res.status(500).json({
                success: false,
                message: 'Hiba történt a regisztráció során',
                error: (error as Error).message
            });
        }
    }
);

// Token eseményfigyelő
oauth2Client.on('tokens', (tokens: { refresh_token?: string | null; access_token?: string | null }) => {
    if (tokens.refresh_token) {
        console.log('Frissítő token:', tokens.refresh_token);
    }
    console.log('Access token:', tokens.access_token);
});

// Admin felhasználó séma
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  });


const Admin = mongoose.model('Admin', adminSchema);

  // JWT titkos kulcs
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Admin bejelentkezési végpont
app.post('/api/admin/login', async (req: Request, res: Response) => {
    try {
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Felhasználónév és jelszó megadása kötelező' });
      }
      
      // Ellenőrizzük a felhasználót (ez csak példa, élesben használj valódi adatbázist)
      const admin = await Admin.findOne({ username });
      
      if (!admin || !(await bcrypt.compare(password, admin.password))) {
        return res.status(401).json({ success: false, message: 'Hibás felhasználónév vagy jelszó' });
      }
      
      // JWT token generálása
      const token = jwt.sign({ username: admin.username }, JWT_SECRET, { expiresIn: '8h' });

      await logAction(req, 'login', {
        adminUser: admin.username
    });
      
      res.json({ success: true, token });
    } catch (error) {
      console.error('Bejelentkezési hiba:', error);
      res.status(500).json({ success: false, message: 'Szerverhiba történt' });
    }
  });


  app.use(cors({
    origin: 'http://localhost:4200', // vagy az Angular alkalmazásod URL-je
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));


// Middleware a JWT token ellenőrzéséhez
function authenticateToken(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      (req as any).user = user;
      next();
    });
  }

  function requireAdmin(req: { session: { user: { isAdmin: any; }; }; }, res: { redirect: (arg0: string) => void; }, next: () => void) {
    if (req.session && req.session.user && req.session.user.isAdmin) {
      next();
    } else {
      res.redirect('/admin/registration');
    }
  }


  // Regisztrációk lekérdezése
app.get('/api/admin/registrations', authenticateToken, async (req: Request, res: Response) => {
    try {
      const registrations = await VIPRegistration.find().sort({ registrationDate: -1 });
      res.json(registrations);
    } catch (error) {
      console.error('Regisztrációk lekérdezése sikertelen:', error);
      res.status(500).json({ message: 'Hiba történt a regisztrációk lekérdezése során' });
    }
  });
  
  // Regisztráció törlése
  app.delete('/api/admin/registrations/:id', authenticateToken, async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const regToDelete = await VIPRegistration.findById(id);
        
        await VIPRegistration.findByIdAndDelete(id);
        
        await logAction(req, 'registration_deleted', {
            targetId: id,
            targetType: 'registration',
            changes: {
                regName: `${regToDelete?.firstName} ${regToDelete?.lastName}`,
                regEmail: regToDelete?.email,
                regLicensePlate: regToDelete?.licensePlate
            }
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Regisztráció törlése sikertelen:', error);
        res.status(500).json({ message: 'Hiba történt a regisztráció törlése során' });
    }
});


  // Státusz módosítása
  app.put('/api/admin/registrations/:id/status', authenticateToken, async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        if (!['accepted', 'rejected', 'maybe'].includes(status)) {
            return res.status(400).json({ message: 'Érvénytelen státusz' });
        }

        const oldReg = await VIPRegistration.findById(id);
        const updatedReg = await VIPRegistration.findByIdAndUpdate(
            id, 
            { status },
            { new: true }
        );

        await logAction(req, 'status_change', {
            targetId: id, // Ez biztosítja, hogy a regisztráció adatai betöltődjenek
            targetType: 'registration',
            changes: {
                from: oldReg?.status,
                to: status
            }
        });

        if (!updatedReg) {
            return res.status(404).json({ message: 'Regisztráció nem található' });
        }

        res.json(updatedReg);
    } catch (error) {
        console.error('Státusz módosítási hiba:', error);
        res.status(500).json({ message: 'Hiba történt a státusz módosítása során' });
    }
});

// Regisztrációk lekérdezése státusz szerint
app.get('/api/admin/registrations/status/:status', authenticateToken, async (req: Request, res: Response) => {
    try {
        const { status } = req.params;
        
        if (!['pending', 'accepted', 'rejected', 'maybe'].includes(status)) {
            return res.status(400).json({ message: 'Érvénytelen státusz' });
        }

        const registrations = await VIPRegistration.find({ status }).sort({ registrationDate: -1 });
        res.json(registrations);
    } catch (error) {
        console.error('Regisztrációk lekérdezése sikertelen:', error);
        res.status(500).json({ message: 'Hiba történt a regisztrációk lekérdezése során' });
    }
});



//admin létrehozása
// async function createAdmin() {
//     const username = 'Kenel'; // Állítsd be az admin felhasználónevet
//     const password = '19Killer84boY'; // Állítsd be az admin jelszót

//     Ellenőrizzük, hogy létezik-e már admin felhasználó
//     const existingAdmin = await Admin.findOne({ username });
//     if (existingAdmin) {
//         console.log('Admin felhasználó már létezik');
//         return;
//     }

//     A jelszó titkosítása
//     const hashedPassword = await bcrypt.hash(password, 10);

//     const newAdmin = new Admin({
//         username,
//         password: hashedPassword
//     });

//     await newAdmin.save();
//     console.log('Admin felhasználó létrehozva!');
// }

// // Hívjuk meg a createAdmin függvényt, ha a scriptet indítjuk
// createAdmin().catch(console.error);


// Szerver indítása
app.listen(PORT, () => {
    console.log(`A szerver fut a ${PORT} porton`);
});