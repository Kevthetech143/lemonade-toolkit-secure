// Secure Server Implementation for Lemonade Toolkit
// This replaces the vulnerable server.js with proper security

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

// Validate required environment variables
const requiredEnvVars = [
    'STRIPE_SECRET_KEY',
    'STRIPE_WEBHOOK_SECRET', 
    'JWT_SECRET',
    'DATABASE_URL',
    'ADMIN_USERNAME',
    'ADMIN_PASSWORD_HASH',
    'FRONTEND_URL'
];

requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
        console.error(`Missing required environment variable: ${varName}`);
        process.exit(1);
    }
});

// Initialize Stripe with secret key
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://api.stripe.com"],
            frameSrc: ["https://js.stripe.com", "https://hooks.stripe.com"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration - restrict to your domain only
app.use(cors({
    origin: process.env.FRONTEND_URL || 'https://lemonade-toolkit.netlify.app',
    credentials: true,
    optionsSuccessStatus: 200
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // limit each IP to 5 requests per windowMs for sensitive endpoints
    message: 'Too many attempts, please try again later.'
});

app.use('/api/', limiter);
app.use('/api/admin/', strictLimiter);
app.use('/api/download/', strictLimiter);

// Database setup (using PostgreSQL with node-postgres)
const { Pool } = require('pg');
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS payments (
                id SERIAL PRIMARY KEY,
                stripe_payment_id VARCHAR(255) UNIQUE NOT NULL,
                stripe_customer_id VARCHAR(255),
                email VARCHAR(255) NOT NULL,
                amount INTEGER NOT NULL,
                currency VARCHAR(10) NOT NULL,
                status VARCHAR(50) NOT NULL,
                access_token VARCHAR(255) UNIQUE,
                token_expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW(),
                accessed_count INTEGER DEFAULT 0,
                last_accessed_at TIMESTAMP,
                metadata JSONB
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS download_logs (
                id SERIAL PRIMARY KEY,
                payment_id INTEGER REFERENCES payments(id),
                ip_address VARCHAR(45),
                user_agent TEXT,
                downloaded_at TIMESTAMP DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id SERIAL PRIMARY KEY,
                token VARCHAR(255) UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        console.log('Database tables initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
        process.exit(1);
    }
}

// Middleware to parse JSON (except for webhook endpoint)
app.use((req, res, next) => {
    if (req.originalUrl === '/webhook') {
        next();
    } else {
        express.json({ limit: '10kb' })(req, res, next);
    }
});

// ============================================
// STRIPE WEBHOOK HANDLER - Critical for security
// ============================================
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
        switch (event.type) {
            case 'checkout.session.completed':
                await handleSuccessfulPayment(event.data.object);
                break;
            case 'payment_intent.succeeded':
                await updatePaymentStatus(event.data.object);
                break;
            case 'payment_intent.payment_failed':
                await handleFailedPayment(event.data.object);
                break;
            default:
                console.log(`Unhandled event type ${event.type}`);
        }

        res.json({ received: true });
    } catch (error) {
        console.error('Webhook processing error:', error);
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

// Handle successful payment
async function handleSuccessfulPayment(session) {
    try {
        // Generate secure access token
        const accessToken = crypto.randomBytes(32).toString('hex');
        const tokenExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        // Store payment record in database
        const query = `
            INSERT INTO payments (
                stripe_payment_id, 
                stripe_customer_id,
                email, 
                amount, 
                currency, 
                status, 
                access_token, 
                token_expires_at,
                metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (stripe_payment_id) 
            DO UPDATE SET 
                status = $6,
                access_token = $7,
                token_expires_at = $8
            RETURNING id
        `;

        const values = [
            session.payment_intent || session.id,
            session.customer,
            session.customer_email || session.customer_details?.email,
            session.amount_total,
            session.currency,
            'completed',
            accessToken,
            tokenExpires,
            JSON.stringify({
                session_id: session.id,
                payment_method: session.payment_method_types?.[0]
            })
        ];

        const result = await pool.query(query, values);
        
        // Send email with access link (implement email service)
        await sendAccessEmail(
            session.customer_email || session.customer_details?.email,
            accessToken
        );

        console.log('Payment processed successfully:', result.rows[0].id);
    } catch (error) {
        console.error('Error handling successful payment:', error);
        throw error;
    }
}

// Update payment status
async function updatePaymentStatus(paymentIntent) {
    try {
        await pool.query(
            'UPDATE payments SET status = $1 WHERE stripe_payment_id = $2',
            ['succeeded', paymentIntent.id]
        );
    } catch (error) {
        console.error('Error updating payment status:', error);
    }
}

// Handle failed payment
async function handleFailedPayment(paymentIntent) {
    try {
        await pool.query(
            'UPDATE payments SET status = $1 WHERE stripe_payment_id = $2',
            ['failed', paymentIntent.id]
        );
    } catch (error) {
        console.error('Error handling failed payment:', error);
    }
}

// ============================================
// SECURE API ENDPOINTS
// ============================================

// Create Stripe checkout session
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'Lemonade Empire Toolkit',
                            description: 'Complete business toolkit with 50+ recipes, profit calculator, and business plan',
                            images: ['https://lemonade-toolkit.netlify.app/lemonade-logo.png'],
                        },
                        unit_amount: 100, // $1.00
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `${process.env.FRONTEND_URL}/verify-payment?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL}/`,
            metadata: {
                product: 'lemonade-toolkit'
            }
        });

        res.json({ 
            sessionId: session.id,
            url: session.url
        });
    } catch (error) {
        console.error('Checkout session creation failed:', error);
        res.status(500).json({ 
            error: 'Failed to create checkout session',
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Verify payment and get access token
app.post('/api/verify-payment', async (req, res) => {
    try {
        const { sessionId } = req.body;

        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID required' });
        }

        // Retrieve session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status !== 'paid') {
            return res.status(403).json({ error: 'Payment not completed' });
        }

        // Check database for access token
        const result = await pool.query(
            'SELECT access_token, token_expires_at FROM payments WHERE stripe_payment_id = $1 OR stripe_payment_id = $2',
            [session.payment_intent, session.id]
        );

        if (result.rows.length === 0) {
            // Payment is valid but not yet processed by webhook
            // Wait a moment for webhook to process
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Check again
            const retryResult = await pool.query(
                'SELECT access_token, token_expires_at FROM payments WHERE stripe_payment_id = $1 OR stripe_payment_id = $2',
                [session.payment_intent, session.id]
            );

            if (retryResult.rows.length === 0) {
                // Manually process if webhook hasn't arrived
                await handleSuccessfulPayment(session);
                
                const finalResult = await pool.query(
                    'SELECT access_token, token_expires_at FROM payments WHERE stripe_payment_id = $1 OR stripe_payment_id = $2',
                    [session.payment_intent, session.id]
                );
                
                if (finalResult.rows.length > 0) {
                    const payment = finalResult.rows[0];
                    const jwtToken = generateJWT(payment.access_token);
                    return res.json({
                        success: true,
                        token: jwtToken,
                        expires: payment.token_expires_at
                    });
                }
            }
        }

        const payment = result.rows[0];
        
        // Check if token is expired
        if (new Date(payment.token_expires_at) < new Date()) {
            return res.status(403).json({ error: 'Access token expired' });
        }

        // Generate JWT for client
        const jwtToken = generateJWT(payment.access_token);

        res.json({
            success: true,
            token: jwtToken,
            expires: payment.token_expires_at
        });
    } catch (error) {
        console.error('Payment verification failed:', error);
        res.status(500).json({ 
            error: 'Payment verification failed',
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Protected download endpoint
app.get('/api/download/:token', authenticateToken, async (req, res) => {
    try {
        const { token } = req.params;
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'];

        // Verify token in database
        const result = await pool.query(
            `SELECT p.* FROM payments p 
             WHERE p.access_token = $1 
             AND p.token_expires_at > NOW()
             AND p.status = 'completed'`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'Invalid or expired access token' });
        }

        const payment = result.rows[0];

        // Update access count and log download
        await pool.query(
            'UPDATE payments SET accessed_count = accessed_count + 1, last_accessed_at = NOW() WHERE id = $1',
            [payment.id]
        );

        await pool.query(
            'INSERT INTO download_logs (payment_id, ip_address, user_agent) VALUES ($1, $2, $3)',
            [payment.id, ipAddress, userAgent]
        );

        // Check if file exists
        const filePath = path.join(__dirname, 'protected-assets', 'lemonade-empire-toolkit.pdf');
        
        try {
            await fs.access(filePath);
        } catch {
            console.error('PDF file not found at:', filePath);
            return res.status(404).json({ error: 'Resource not found' });
        }

        // Set secure headers for download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="Lemonade-Empire-Toolkit.pdf"');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        
        // Stream file to client
        res.sendFile(filePath);
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Download failed' });
    }
});

// ============================================
// ADMIN ENDPOINTS (Protected)
// ============================================

// Admin login
app.post('/api/admin/login', strictLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Verify admin credentials
        if (username !== process.env.ADMIN_USERNAME) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate admin session token
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours

        await pool.query(
            'INSERT INTO admin_sessions (token, expires_at) VALUES ($1, $2)',
            [sessionToken, expiresAt]
        );

        // Generate JWT for admin
        const adminJWT = jwt.sign(
            { 
                role: 'admin',
                sessionToken,
                exp: Math.floor(expiresAt.getTime() / 1000)
            },
            process.env.JWT_SECRET
        );

        res.json({
            success: true,
            token: adminJWT,
            expires: expiresAt
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Admin middleware
async function authenticateAdmin(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Admin authentication required' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        // Verify session in database
        const result = await pool.query(
            'SELECT * FROM admin_sessions WHERE token = $1 AND expires_at > NOW()',
            [decoded.sessionToken]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }

        req.admin = decoded;
        next();
    } catch (error) {
        console.error('Admin auth error:', error);
        res.status(401).json({ error: 'Authentication failed' });
    }
}

// Get sales statistics (admin only)
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const stats = await pool.query(`
            SELECT 
                COUNT(*) as total_sales,
                SUM(amount) as total_revenue,
                COUNT(DISTINCT email) as unique_customers,
                AVG(amount) as average_sale,
                MAX(created_at) as last_sale,
                COUNT(CASE WHEN created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as sales_today,
                COUNT(CASE WHEN created_at > NOW() - INTERVAL '7 days' THEN 1 END) as sales_week,
                COUNT(CASE WHEN created_at > NOW() - INTERVAL '30 days' THEN 1 END) as sales_month
            FROM payments
            WHERE status = 'completed'
        `);

        const downloads = await pool.query(`
            SELECT 
                COUNT(*) as total_downloads,
                COUNT(DISTINCT payment_id) as unique_downloaders,
                COUNT(CASE WHEN downloaded_at > NOW() - INTERVAL '24 hours' THEN 1 END) as downloads_today
            FROM download_logs
        `);

        res.json({
            sales: stats.rows[0],
            downloads: downloads.rows[0]
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Get recent orders (admin only)
app.get('/api/admin/orders', authenticateAdmin, async (req, res) => {
    try {
        const { limit = 50, offset = 0 } = req.query;

        const orders = await pool.query(`
            SELECT 
                id,
                email,
                amount,
                currency,
                status,
                created_at,
                accessed_count,
                last_accessed_at
            FROM payments
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        `, [limit, offset]);

        res.json({
            orders: orders.rows,
            total: orders.rowCount
        });
    } catch (error) {
        console.error('Orders fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// Generate manual access token (admin only)
app.post('/api/admin/generate-access', authenticateAdmin, async (req, res) => {
    try {
        const { email, reason } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email required' });
        }

        const accessToken = crypto.randomBytes(32).toString('hex');
        const tokenExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        await pool.query(`
            INSERT INTO payments (
                stripe_payment_id,
                email,
                amount,
                currency,
                status,
                access_token,
                token_expires_at,
                metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            'manual_' + Date.now(),
            email,
            0,
            'usd',
            'completed',
            accessToken,
            tokenExpires,
            JSON.stringify({ manual: true, reason, generated_by: 'admin' })
        ]);

        const accessUrl = `${process.env.FRONTEND_URL}/access?token=${accessToken}`;

        res.json({
            success: true,
            accessToken,
            accessUrl,
            expires: tokenExpires
        });
    } catch (error) {
        console.error('Generate access error:', error);
        res.status(500).json({ error: 'Failed to generate access' });
    }
});

// ============================================
// UTILITY FUNCTIONS
// ============================================

// Generate JWT token
function generateJWT(accessToken) {
    return jwt.sign(
        { 
            accessToken,
            type: 'access'
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );
}

// Authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = decoded;
        next();
    });
}

// Send access email
async function sendAccessEmail(email, accessToken) {
    try {
        // Implement your email service here
        // For now, we'll just log it
        console.log(`Access email would be sent to ${email} with token: ${accessToken}`);
        
        // Example with nodemailer (uncomment and configure):
        /*
        const nodemailer = require('nodemailer');
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: false,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const accessUrl = `${process.env.FRONTEND_URL}/access?token=${accessToken}`;
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your Lemonade Empire Toolkit Access',
            html: `
                <h1>Thank you for your purchase!</h1>
                <p>Click the link below to access your Lemonade Empire Toolkit:</p>
                <a href="${accessUrl}" style="background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Access Your Toolkit</a>
                <p>This link will expire in 7 days for security reasons.</p>
                <p>If you have any issues, please contact support.</p>
            `
        });
        */
    } catch (error) {
        console.error('Email sending failed:', error);
        // Don't throw - we don't want to fail the payment process if email fails
    }
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV
    });
});

// Start server
async function startServer() {
    try {
        await initDatabase();
        
        app.listen(PORT, () => {
            console.log(`Secure server running on port ${PORT}`);
            console.log(`Environment: ${process.env.NODE_ENV}`);
            console.log('Security features enabled:');
            console.log('- Helmet security headers ✓');
            console.log('- CORS restrictions ✓');
            console.log('- Rate limiting ✓');
            console.log('- JWT authentication ✓');
            console.log('- Webhook signature verification ✓');
            console.log('- SQL injection protection ✓');
            console.log('- Admin authentication ✓');
        });
    } catch (error) {
        console.error('Server startup failed:', error);
        process.exit(1);
    }
}

startServer();

module.exports = app;