require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const validator = require('validator');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'ZEMA_SECURE_JWT_2025_DO_NOT_SHARE';

// Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('x Supabase configuration missing');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: { persistSession: false },
    db: { schema: 'public' }
});

// Create directories
if (!fs.existsSync('./public')) fs.mkdirSync('./public', { recursive: true });
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads', { recursive: true });
if (!fs.existsSync('./uploads/payments')) fs.mkdirSync('./uploads/payments', { recursive: true });

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './uploads/payments/');
    },
    filename: function (req, file, cb) {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif|pdf/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('File type not allowed'));
        }
    }
});

// Helper functions
const generateReferralCode = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = "";
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return 'ZEMA' + code;
};

const generateTransactionId = () => {
    return 'TX' + Date.now() + Math.floor(Math.random() * 1000);
};

const sendNotification = async (userId, title, message, type = 'system') => {
    try {
        await supabase
            .from('notifications')
            .insert({
                user_id: userId,
                title: title,
                message: message,
                type: type,
                is_read: false,
                created_at: new Date().toISOString()
            });
        console.log(`✓ Notification sent to user ${userId}: ${title}`);
    } catch (error) {
        console.error('Error sending notification:', error);
    }
};

const getSetting = async (key, defaultValue = "1") => {
    try {
        const { data: setting, error } = await supabase
            .from('settings')
            .select('value')
            .eq('key', key)
            .single();
        
        if (error || !setting) {
            console.log(`⚠️ Setting ${key} not found, using default: ${defaultValue}`);
            return defaultValue;
        }
        return setting.value;
    } catch (error) {
        console.error(`Error getting setting ${key}:`, error);
        return defaultValue;
    }
};

const updateSetting = async (key, value) => {
    try {
        const { data: existing } = await supabase
            .from('settings')
            .select('*')
            .eq('key', key)
            .single();
        
        if (existing) {
            await supabase
                .from('settings')
                .update({
                    value: value.toString(),
                    updated_at: new Date().toISOString()
                })
                .eq('key', key);
        } else {
            await supabase
                .from('settings')
                .insert({
                    key: key,
                    value: value.toString(),
                    category: 'general',
                    is_public: false,
                    created_at: new Date().toISOString()
                });
        }
        return true;
    } catch (error) {
        console.error('Error updating setting:', error);
        return false;
    }
};

// Helper function to log user activity
const logUserActivity = async (userId, activityType, description, amount = 0, referenceId = null, req = null) => {
    try {
        await supabase
            .from('user_activities')
            .insert({
                user_id: userId,
                activity_type: activityType,
                description: description,
                amount: amount,
                reference_id: referenceId,
                ip_address: req ? req.ip : null,
                user_agent: req ? req.headers['user-agent'] : null,
                created_at: new Date().toISOString()
            });
        console.log(`✓ Activity logged for user ${userId}: ${activityType}`);
    } catch (error) {
        console.error('Error logging activity:', error);
    }
};

// Middleware - Authentication
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({
                success: false,
                message: 'Token required'
            });
        }
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }
        const decoded = jwt.verify(token, JWT_SECRET);

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', decoded.userId)
            .single();

        if (error || !user) {
            return res.status(403).json({
                success: false,
                message: 'User not found'
            });
        }
        if (user.is_banned) {
            return res.status(403).json({
                success: false,
                message: 'Account banned. Please contact support'
            });
        }
        if (!user.is_active && req.path !== '/api/verify-payment') {
            return res.status(403).json({
                success: false,
                message: 'Account not active. Please complete payment'
            });
        }
        req.user = user;
        next();
    } catch (error) {
        console.error("Token authentication error:", error.message);
        return res.status(403).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }
};

const authenticateAdmin = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({
                success: false,
                message: 'Admin token required'
            });
        }
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }
        const decoded = jwt.verify(token, JWT_SECRET);

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', decoded.userId)
            .single();

        if (error || !user) {
            return res.status(403).json({
                success: false,
                message: 'User not found'
            });
        }
        if (!user.is_admin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        req.admin = user;
        next();
    } catch (error) {
        console.error('Admin authentication error:', error.message);
        return res.status(403).json({
            success: false,
            message: 'Invalid token'
        });
    }
};

const addToPlatformBalance = async (amount) => {
    try {
        const currentBalance = parseFloat(await getSetting('platform_balance', '0'));
        const newBalance = currentBalance + parseFloat(amount);
        await updateSetting('platform_balance', newBalance.toString());
        console.log(`✓ Added $${amount} to platform balance. New balance: $${newBalance}`);
        return true;
    } catch (error) {
        console.error('Error updating platform balance:', error);
        return false;
    }
};

// Initialize database
const initializeDatabase = async () => {
    try {
        console.log(`✓ Checking database...`);

        // Test connection
        const { data, error } = await supabase.from('users').select('count').limit(1);
        if (error) {
            console.error("Database connection error:", error.message);
            throw error;
        }

        // Create admin if not exists
        const { data: admin, error: adminError } = await supabase
            .from('users')
            .select('*')
            .eq('email', 'julianbeal16@gmail.com')
            .single();

        if (adminError || !admin) {
            const hashedPassword = await bcrypt.hash('0938361689Aa@', 10);
            const { error: insertError } = await supabase
                .from('users')
                .insert({
                    email: 'julianbeal16@gmail.com',
                    password: hashedPassword,
                    full_name: 'Main Admin',
                    referral_code: 'ZEMAADMIN',
                    balance: 10000.00,
                    total_earnings: 0.00,
                    is_active: true,
                    is_admin: true,
                    is_banned: false,
                    email_verified: true,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                });

            if (insertError) {
                console.error("Admin creation error:", insertError);
            } else {
                console.log("✓ Main admin created");
            }
        } else {
            if (!admin.is_admin) {
                await supabase
                    .from('users')
                    .update({ is_admin: true })
                    .eq('email', 'julianbeal16@gmail.com');
                console.log("✓ Admin permissions updated");
            }
        }

        // Add second admin
        const { data: secondAdmin, error: secondAdminError } = await supabase
            .from('users')
            .select('*')
            .eq('email', 'laulau22lau@gmail.com')
            .single();

        if (secondAdminError || !secondAdmin) {
            const hashedPassword2 = await bcrypt.hash('0000000000', 10);
            await supabase
                .from('users')
                .insert({
                    email: 'laulau22lau@gmail.com',
                    password: hashedPassword2,
                    full_name: 'Second Admin',
                    referral_code: 'ZEMAADMIN2',
                    balance: 5000.00,
                    total_earnings: 0.00,
                    is_active: true,
                    is_admin: true,
                    is_banned: false,
                    email_verified: true,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                });
            console.log('✓ Second admin created');
        } else {
            if (!secondAdmin.is_admin) {
                await supabase
                    .from('users')
                    .update({ is_admin: true })
                    .eq('email', 'laulau22lau@gmail.com');
            }
        }

        // Default settings
        const defaultSettings = [
            { key: 'site_name', value: 'ZEMA Platform', category: 'general', is_public: true },
            { key: 'site_description', value: 'Your Gateway to Financial Freedom', category: 'general', is_public: true },
            { key: 'registration_fee', value: '1', category: 'financial', is_public: true },
            { key: 'min_withdrawal', value: '3', category: 'financial', is_public: true },
            { key: 'referral_commission', value: '50', category: 'financial', is_public: true },
            { key: 'payment_wallet', value: 'julianbeal16@gmail.com', category: 'payment', is_public: false },
            { key: 'support_link', value: 'https://t.me/zema_support', category: 'support', is_public: true },
            { key: 'contact_email', value: 'support@zema.com', category: 'support', is_public: true },
            { key: 'currency', value: 'USD', category: 'general', is_public: true },
            { key: 'site_url', value: 'https://zema-platform.onrender.com', category: 'general', is_public: true },
            { key: 'version', value: '3.0.0', category: 'system', is_public: false },
            { key: 'platform_balance', value: '0', category: 'financial', is_public: false },
            { key: 'weekly_contest_ticket_price', value: '1', category: 'contest', is_public: true },
            { key: 'weekly_contest_prize', value: '100', category: 'contest', is_public: true }
        ];

        for (const setting of defaultSettings) {
            const { data: existing } = await supabase
                .from('settings')
                .select('*')
                .eq('key', setting.key)
                .single();

            if (!existing) {
                await supabase
                    .from('settings')
                    .insert({
                        ...setting,
                        created_at: new Date().toISOString(),
                        updated_at: new Date().toISOString()
                    });
            }
        }

        // Create default weekly contest if not exists
        const { data: existingContest } = await supabase
            .from('contests')
            .select('*')
            .eq('title', 'Weekly Mega Jackpot')
            .single();

        if (!existingContest) {
            await supabase
                .from('contests')
                .insert({
                    title: 'Weekly Mega Jackpot',
                    description: 'Buy tickets for a chance to win $100!',
                    ticket_price: 1.00,
                    prize_amount: 100.00,
                    max_participants: 100,
                    max_tickets_per_user: 5,
                    auto_draw_number: false,
                    status: 'active',
                    start_date: new Date().toISOString(),
                    end_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
                    created_at: new Date().toISOString()
                });
            console.log('✓ Default contest created');
        }

        console.log('✓ Database initialized successfully');
        return true;
    } catch (error) {
        console.error('✗ Database initialization error:', error);
        return false;
    }
};

// ===================== USER ROUTES ================================

// 1. Register - ✅ المصحح
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, referralCode } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email'
            });
        }
        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters'
            });
        }

        // Check if user exists
        const { data: existingUser, error: existingError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Email already registered'
            });
        }

        // Check referral code
        let referrerId = null;
        if (referralCode) {
            const { data: referrer, error: referrerError } = await supabase
                .from('users')
                .select('id, referral_code')
                .eq('referral_code', referralCode)
                .eq('is_active', true)
                .single();
            if (referrer) {
                referrerId = referrer.id;
            }
        }

        // Create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newReferralCode = generateReferralCode();

        const { data: user, error: userError } = await supabase
            .from('users')
            .insert({
                email: email,
                password: hashedPassword,
                referral_code: newReferralCode,
                referred_by: referrerId ? referralCode : null,
                balance: 0.00,
                total_earnings: 0.00,
                is_active: false,
                is_admin: false,
                is_banned: false,
                email_verified: false,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select()
            .single();

        if (userError) {
            throw userError;
        }

        // Log user activity
        await logUserActivity(
            user.id,
            'registration',
            'User registered with email',
            0,
            user.id,
            req
        );

        // Create referral record
        if (referrerId) {
            await supabase
                .from('referrals')
                .insert({
                    referrer_id: referrerId,
                    referred_id: user.id,
                    status: 'pending',
                    commission_amount: 0.00,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                });
        }

        // ✅ Create payment record - الإصلاح هنا
        const registrationFee = await getSetting('registration_fee', '1');
        const paymentWallet = await getSetting('payment_wallet', 'julianbeal16@gmail.com');

        // تأكد من أن القيمة رقمية
        let feeAmount = parseFloat(registrationFee);
        if (isNaN(feeAmount) || feeAmount <= 0) {
            feeAmount = 1.00;
            console.log(`⚠️ Registration fee is invalid (${registrationFee}), using default 1.00`);
        }

        const { data: payment, error: paymentError } = await supabase
            .from('payments')
            .insert({
                user_id: user.id,
                email: user.email,
                payment_method: 'email',
                amount: feeAmount, // ✅ قيمة مؤكدة
                transaction_id: generateTransactionId(),
                status: 'pending',
                created_at: new Date().toISOString()
            })
            .select()
            .single();

        if (paymentError) {
            console.error('Payment creation error:', paymentError);
            throw paymentError;
        }

        // Send notification to admin
        const { data: admin } = await supabase
            .from('users')
            .select('id')
            .eq('is_admin', true)
            .limit(1)
            .single();

        if (admin) {
            await sendNotification(
                admin.id,
                "New Registration",
                `New user: ${email}`,
                'registration'
            );
        }

        res.status(201).json({
            success: true,
            message: 'Registration successful. Complete payment to activate your account',
            data: {
                user: {
                    id: user.id,
                    email: user.email,
                    referral_code: user.referral_code
                },
                payment: {
                    id: payment.id,
                    amount: feeAmount,
                    wallet: paymentWallet,
                    transaction_id: payment.transaction_id
                }
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed. Please try again'
        });
    }
});

// 2. Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Check if banned
        if (user.is_banned) {
            return res.status(403).json({
                success: false,
                message: 'Account banned. Please contact support'
            });
        }

        // Check if active
        if (!user.is_active) {
            return res.status(403).json({
                success: false,
                message: 'Account not active. Please complete payment'
            });
        }

        // Update last login
        await supabase
            .from('users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', user.id);

        // Log user activity
        await logUserActivity(
            user.id,
            'login',
            'User logged in',
            0,
            null,
            req
        );

        // Create token
        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                isAdmin: user.is_admin
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                token: token,
                user: {
                    id: user.id,
                    email: user.email,
                    balance: user.balance,
                    total_earnings: user.total_earnings,
                    referral_code: user.referral_code,
                    is_admin: user.is_admin,
                    is_active: user.is_active
                }
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again'
        });
    }
});

// 3. User Dashboard
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const user = req.user;

        // Get referrals
        const { data: referrals } = await supabase
            .from('referrals')
            .select('*')
            .eq('referrer_id', user.id);

        // Get games
        const { data: games } = await supabase
            .from('game_links')
            .select('*')
            .eq('is_active', true)
            .order('created_at', { ascending: false });

        // Get notifications
        const { data: notifications } = await supabase
            .from('notifications')
            .select('*')
            .eq('user_id', user.id)
            .eq('is_read', false)
            .order('created_at', { ascending: false })
            .limit(10);

        // Get withdrawals
        const { data: withdrawals } = await supabase
            .from('withdrawals')
            .select('*')
            .eq('user_id', user.id)
            .order('created_at', { ascending: false });

        // Get active contests
        const { data: contests } = await supabase
            .from('contests')
            .select('*')
            .eq('status', 'active')
            .order('created_at', { ascending: false });

        // Get user's contest participations
        const { data: participations } = await supabase
            .from('contest_participations')
            .select('*, contest:contest_id(title, prize_amount, status)')
            .eq('user_id', user.id);

        // Calculate active referrals
        const activeReferrals = referrals ? referrals.filter(r => r.status === 'active').length : 0;

        res.json({
            success: true,
            data: {
                user: {
                    id: user.id,
                    email: user.email,
                    balance: user.balance,
                    total_earnings: user.total_earnings,
                    referral_code: user.referral_code,
                    is_admin: user.is_admin,
                    is_active: user.is_active
                },
                stats: {
                    total_referrals: referrals ? referrals.length : 0,
                    active_referrals: activeReferrals,
                    pending_referrals: referrals ? referrals.filter(r => r.status === 'pending').length : 0,
                    total_games: games ? games.length : 0,
                    unread_notifications: notifications ? notifications.length : 0,
                    total_withdrawals: withdrawals ? withdrawals.length : 0,
                    total_contests: contests ? contests.length : 0,
                    my_participations: participations ? participations.length : 0
                },
                referral_link: `${req.protocol}://${req.get('host')}/register?ref=${user.referral_code}`,
                games: games || [],
                referrals: referrals || [],
                notifications: notifications || [],
                withdrawals: withdrawals || [],
                contests: contests || [],
                contest_participations: participations || []
            }
        });
    } catch (error) {
        console.error('Dashboard load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load dashboard'
        });
    }
});

// 4. Withdraw
app.post('/api/withdraw', authenticateToken, async (req, res) => {
    try {
        const { amount, wallet_address } = req.body;
        const user = req.user;

        if (!amount || !wallet_address) {
            return res.status(400).json({
                success: false,
                message: 'Amount and wallet address are required'
            });
        }

        const minWithdrawal = parseFloat(await getSetting('min_withdrawal', '3'));
        const amountNum = parseFloat(amount);

        if (amountNum < minWithdrawal) {
            return res.status(400).json({
                success: false,
                message: `Minimum withdrawal is $${minWithdrawal}`
            });
        }

        if (user.balance < amountNum) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }

        // Deduct amount
        const newBalance = user.balance - amountNum;
        await supabase
            .from('users')
            .update({
                balance: newBalance,
                updated_at: new Date().toISOString()
            })
            .eq('id', user.id);

        // Create withdrawal
        const { data: withdrawal, error: withdrawalError } = await supabase
            .from('withdrawals')
            .insert({
                user_id: user.id,
                email: user.email,
                amount: amountNum,
                wallet_address: wallet_address,
                wallet_type: 'USDT',
                status: 'pending',
                created_at: new Date().toISOString()
            })
            .select()
            .single();

        if (withdrawalError) {
            throw withdrawalError;
        }

        // Log user activity
        await logUserActivity(
            user.id,
            'withdrawal_request',
            'Withdrawal request submitted',
            amountNum,
            withdrawal.id,
            req
        );

        // Send notification to admin
        const { data: admin } = await supabase
            .from('users')
            .select('id')
            .eq('is_admin', true)
            .limit(1)
            .single();

        if (admin) {
            await sendNotification(
                admin.id,
                'New Withdrawal Request',
                `Withdrawal request of $${amountNum} from ${user.email} to ${wallet_address}`,
                'withdrawal'
            );
        }

        // Send notification to user
        await sendNotification(
            user.id,
            "Withdrawal Request Submitted",
            `Your withdrawal request of $${amountNum} has been submitted. It will be processed within 24-48 hours.`,
            'withdrawal'
        );

        res.json({
            success: true,
            message: 'Withdrawal request submitted successfully',
            data: {
                withdrawal_id: withdrawal.id,
                new_balance: newBalance
            }
        });
    } catch (error) {
        console.error('Withdrawal error:', error);

        // Rollback balance
        try {
            await supabase
                .from('users')
                .update({
                    balance: req.user.balance,
                    updated_at: new Date().toISOString()
                })
                .eq('id', req.user.id);
        } catch (rollbackError) {
            console.error('Balance rollback error:', rollbackError);
        }

        res.status(500).json({
            success: false,
            message: 'Failed to submit withdrawal request'
        });
    }
});

// 5. Get games
app.get('/api/games', authenticateToken, async (req, res) => {
    try {
        const { data: games, error } = await supabase
            .from('game_links')
            .select('*')
            .eq('is_active', true)
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }
        res.json({
            success: true,
            data: games || []
        });
    } catch (error) {
        console.error('Games load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load games'
        });
    }
});

// 6. Get referrals
app.get('/api/referrals', authenticateToken, async (req, res) => {
    try {
        const user = req.user;

        const { data: referrals, error } = await supabase
            .from('referrals')
            .select('*')
            .eq('referrer_id', user.id)
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }

        // Calculate stats
        const stats = {
            total: referrals ? referrals.length : 0,
            active: referrals ? referrals.filter(r => r.status === 'active').length : 0,
            pending: referrals ? referrals.filter(r => r.status === 'pending').length : 0,
            total_commission: referrals ? referrals.reduce((sum, r) => sum + (r.commission_amount || 0), 0) : 0
        };

        res.json({
            success: true,
            data: {
                stats: stats,
                referrals: referrals || []
            }
        });
    } catch (error) {
        console.error('Referrals load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load referrals'
        });
    }
});

// 7. Buy contest ticket
app.post('/api/contests/:id/buy', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const user = req.user;

        // Get contest
        const { data: contest, error: contestError } = await supabase
            .from('contests')
            .select('*')
            .eq('id', id)
            .eq('status', 'active')
            .single();

        if (contestError || !contest) {
            return res.status(404).json({
                success: false,
                message: 'Contest not found or not active'
            });
        }

        // Check if contest reached max participants
        const { count: totalParticipants } = await supabase
            .from('contest_participations')
            .select('*', { count: 'exact', head: true })
            .eq('contest_id', id);

        if (totalParticipants >= contest.max_participants) {
            return res.status(400).json({
                success: false,
                message: 'Contest has reached maximum participants'
            });
        }

        // Check user's current tickets for this contest
        const { count: userTickets } = await supabase
            .from('contest_participations')
            .select('*', { count: 'exact', head: true })
            .eq('contest_id', id)
            .eq('user_id', user.id);

        if (userTickets >= contest.max_tickets_per_user) {
            return res.status(400).json({
                success: false,
                message: `You can only buy ${contest.max_tickets_per_user} ticket(s) for this contest`
            });
        }

        // Check user balance
        if (user.balance < contest.ticket_price) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }

        // Generate random ticket number
        const ticketNumber = Math.floor(Math.random() * contest.max_participants) + 1;

        // Deduct ticket price
        const newBalance = user.balance - contest.ticket_price;
        await supabase
            .from('users')
            .update({
                balance: newBalance,
                updated_at: new Date().toISOString()
            })
            .eq('id', user.id);

        // Create participation
        const { data: participation, error: participationError } = await supabase
            .from('contest_participations')
            .insert({
                contest_id: contest.id,
                user_id: user.id,
                tickets: 1,
                ticket_number: ticketNumber,
                created_at: new Date().toISOString()
            })
            .select()
            .single();

        if (participationError) {
            throw participationError;
        }

        // Add to platform balance
        await addToPlatformBalance(contest.ticket_price);

        // Log user activity
        await logUserActivity(
            user.id,
            'ticket_purchased',
            `Purchased ticket for contest "${contest.title}"`,
            contest.ticket_price,
            participation.id,
            req
        );

        // Send notification
        await sendNotification(
            user.id,
            "Ticket Purchased",
            `You bought a ticket for "${contest.title}". Your ticket number is ${ticketNumber}. Good luck!`,
            'contest'
        );

        res.json({
            success: true,
            message: 'Ticket purchased successfully',
            data: {
                participation_id: participation.id,
                ticket_number: ticketNumber,
                new_balance: newBalance,
                contest: contest
            }
        });
    } catch (error) {
        console.error('Ticket purchase error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to purchase ticket'
        });
    }
});

// 8. Verify payment (upload proof)
app.post('/api/verify-payment', upload.single('proof'), async (req, res) => {
    try {
        const { payment_id, transaction_id } = req.body;
        const file = req.file;

        if (!payment_id || !transaction_id || !file) {
            return res.status(400).json({
                success: false,
                message: 'Incomplete data'
            });
        }

        // Update payment
        const { data: payment, error } = await supabase
            .from('payments')
            .update({
                proof_image: file.filename,
                transaction_id: transaction_id,
                updated_at: new Date().toISOString()
            })
            .eq('id', payment_id)
            .select()
            .single();

        if (error) {
            throw error;
        }

        // Send notification to admin
        const { data: admin } = await supabase
            .from('users')
            .select('id')
            .eq('is_admin', true)
            .limit(1)
            .single();

        if (admin) {
            await sendNotification(
                admin.id,
                "New Payment Proof",
                `Payment proof uploaded for transaction ${transaction_id}`,
                'payment'
            );
        }

        res.json({
            success: true,
            message: 'Payment proof uploaded successfully'
        });
    } catch (error) {
        console.error('Payment proof upload error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to upload payment proof'
        });
    }
});

// 9. Get user activities
app.get('/api/user/activities', authenticateToken, async (req, res) => {
    try {
        const user = req.user;
        const { limit = 50, page = 1 } = req.query;
        const offset = (page - 1) * limit;

        const { data: activities, error } = await supabase
            .from('user_activities')
            .select('*', { count: 'exact' })
            .eq('user_id', user.id)
            .order('created_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (error) {
            throw error;
        }
        res.json({
            success: true,
            data: {
                activities: activities || [],
                total: activities?.length || 0
            }
        });
    } catch (error) {
        console.error('Activities load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load activities'
        });
    }
});

// =============================================================== ADMIN ROUTES ===============================================================

// 1. Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // Find user
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Check admin permissions
        if (!user.is_admin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }

        // Create token
        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                isAdmin: true
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Admin login successful',
            data: {
                token: token,
                admin: {
                    id: user.id,
                    email: user.email,
                    name: user.full_name || user.email
                }
            }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({
            success: false,
            message: 'Admin login failed'
        });
    }
});

// 2. Admin dashboard
app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
    try {
        // User statistics
        const { count: totalUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });

        const { count: activeUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('is_active', true);

        const { count: bannedUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('is_banned', true);

        // Payment statistics
        const { data: payments } = await supabase
            .from('payments')
            .select('amount, status');

        const { count: pendingPayments } = await supabase
            .from('payments')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'pending');

        const totalDeposits = payments ? payments
            .filter(p => p.status === 'approved')
            .reduce((sum, p) => sum + (p.amount || 0), 0) : 0;

        // Withdrawal statistics
        const { data: withdrawals } = await supabase
            .from('withdrawals')
            .select('amount, status');

        const { count: pendingWithdrawals } = await supabase
            .from('withdrawals')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'pending');

        const totalWithdrawals = withdrawals ? withdrawals
            .filter(w => w.status === 'completed')
            .reduce((sum, w) => sum + (w.amount || 0), 0) : 0;

        // Referral statistics
        const { data: referrals } = await supabase
            .from('referrals')
            .select('commission_amount');

        const totalCommissions = referrals ? referrals
            .reduce((sum, r) => sum + (r.commission_amount || 0), 0) : 0;

        // Contest statistics
        const { data: contests } = await supabase
            .from('contests')
            .select('*');

        const { data: participations } = await supabase
            .from('contest_participations')
            .select('*');

        const totalContestTickets = participations ? participations.length : 0;
        const totalContestRevenue = contests ? contests.reduce((sum, c) => {
            const contestParticipations = participations ? participations.filter(p => p.contest_id === c.id).length : 0;
            return sum + (c.ticket_price * contestParticipations);
        }, 0) : 0;

        // Platform balance
        const platformBalance = await getSetting('platform_balance', '0');

        // Recent users (5)
        const { data: recentUsers } = await supabase
            .from('users')
            .select('id, email, created_at, is_active, balance')
            .order('created_at', { ascending: false })
            .limit(5);

        // Recent payments (5)
        const { data: recentPayments } = await supabase
            .from('payments')
            .select('id, email, amount, status, created_at')
            .order('created_at', { ascending: false })
            .limit(5);

        res.json({
            success: true,
            data: {
                stats: {
                    total_users: totalUsers || 0,
                    active_users: activeUsers || 0,
                    banned_users: bannedUsers || 0,
                    pending_payments: pendingPayments || 0,
                    pending_withdrawals: pendingWithdrawals || 0,
                    total_deposits: totalDeposits,
                    total_withdrawals: totalWithdrawals,
                    total_commissions: totalCommissions,
                    platform_balance: parseFloat(platformBalance),
                    total_contests: contests ? contests.length : 0,
                    total_contest_tickets: totalContestTickets,
                    total_contest_revenue: totalContestRevenue,
                    success_rate: totalDeposits > 0 ?
                        ((totalDeposits - totalWithdrawals) / totalDeposits * 100).toFixed(2) : 0
                },
                recent_users: recentUsers || [],
                recent_payments: recentPayments || []
            }
        });
    } catch (error) {
        console.error('Admin dashboard load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load admin dashboard'
        });
    }
});

// 3. Get all users
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, search = "" } = req.query;
        const offset = (page - 1) * limit;

        let query = supabase
            .from('users')
            .select('*', { count: 'exact' })
            .order('created_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (search) {
            query = query.or(`email.ilike.%${search}%,referral_code.ilike.%${search}%`);
        }

        const { data: users, count, error } = await query;

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            data: {
                users: users || [],
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: count || 0,
                    total_pages: Math.ceil((count || 0) / limit)
                }
            }
        });
    } catch (error) {
        console.error('Users load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load users'
        });
    }
});

// 4. Get user details
app.get('/api/admin/users/:id/details', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Get user data
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('id', id)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Get user referrals
        const { data: referrals } = await supabase
            .from('referrals')
            .select('*, referred_user:referred_id(email, created_at, balance, is_active)')
            .eq('referrer_id', id)
            .order('created_at', { ascending: false });

        // Get user payments
        const { data: payments } = await supabase
            .from('payments')
            .select('*')
            .eq('user_id', id)
            .order('created_at', { ascending: false });

        // Get user withdrawals
        const { data: withdrawals } = await supabase
            .from('withdrawals')
            .select('*')
            .eq('user_id', id)
            .order('created_at', { ascending: false });

        // Get user contest participations
        const { data: contestParticipations } = await supabase
            .from('contest_participations')
            .select('*, contest:contest_id(title, prize_amount, status)')
            .eq('user_id', id)
            .order('created_at', { ascending: false });

        // Get user activities
        const { data: activities } = await supabase
            .from('user_activities')
            .select('*')
            .eq('user_id', id)
            .order('created_at', { ascending: false })
            .limit(20);

        res.json({
            success: true,
            data: {
                user: user,
                stats: {
                    total_referrals: referrals ? referrals.length : 0,
                    active_referrals: referrals ? referrals.filter(r => r.status === 'active').length : 0,
                    total_payments: payments ? payments.length : 0,
                    total_withdrawals: withdrawals ? withdrawals.length : 0,
                    total_contest_participations: contestParticipations ? contestParticipations.length : 0,
                    total_activities: activities ? activities.length : 0
                },
                referrals: referrals || [],
                payments: payments || [],
                withdrawals: withdrawals || [],
                contest_participations: contestParticipations || [],
                activities: activities || []
            }
        });
    } catch (error) {
        console.error('User details error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load user details'
        });
    }
});

// 5. Adjust user balance
app.post('/api/admin/users/:id/adjust-balance', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, operation, reason } = req.body; // operation: 'add' or 'subtract'

        if (!amount || !operation || !['add', 'subtract'].includes(operation)) {
            return res.status(400).json({
                success: false,
                message: 'Amount, operation (add/subtract), and reason are required'
            });
        }

        // Get current user
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('balance, email')
            .eq('id', id)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const amountNum = parseFloat(amount);
        let newBalance;

        if (operation == 'add') {
            newBalance = parseFloat(user.balance) + amountNum;
        } else {
            newBalance = parseFloat(user.balance) - amountNum;
            if (newBalance < 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Insufficient balance'
                });
            }
        }

        // Update user balance
        await supabase
            .from('users')
            .update({
                balance: newBalance,
                updated_at: new Date().toISOString()
            })
            .eq('id', id);

        // Log the adjustment
        await supabase
            .from('balance_adjustments')
            .insert({
                user_id: id,
                admin_id: req.admin.id,
                amount: amountNum,
                operation: operation,
                reason: reason || 'Admin adjustment',
                previous_balance: user.balance,
                new_balance: newBalance,
                created_at: new Date().toISOString()
            });

        // Log user activity
        await logUserActivity(
            id,
            'balance_adjustment',
            `Balance ${operation == 'add' ? 'increased' : 'decreased'} by admin`,
            amountNum,
            null,
            req
        );

        // Send notification to user
        await sendNotification(
            id,
            "Balance Updated",
            `Your balance has been ${operation == 'add' ? 'increased' : 'decreased'} by $${amountNum}. Reason: ${reason || 'Admin adjustment'}. New balance: $${newBalance}`,
            'balance'
        );

        res.json({
            success: true,
            message: `Balance ${operation == 'add' ? 'added' : 'subtracted'} successfully`,
            data: {
                user_id: id,
                previous_balance: user.balance,
                new_balance: newBalance,
                adjustment: amountNum,
                operation: operation
            }
        });
    } catch (error) {
        console.error('Balance adjustment error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to adjust balance'
        });
    }
});

// 6. Activate/deactivate user
app.post('/api/admin/users/:id/toggle', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { action } = req.body;

        if (!action || !['activate', 'deactivate'].includes(action)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid action'
            });
        }

        const is_active = action === 'activate';

        const { data: user, error } = await supabase
            .from('users')
            .update({
                is_active: is_active,
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .select()
            .single();

        if (error) {
            throw error;
        }

        // Send notification to user
        await sendNotification(
            id,
            is_active ? "Account Activated" : "Account Deactivated",
            is_active
                ? "Your account has been activated successfully. You can now use all platform features."
                : "Your account has been temporarily deactivated. Please contact support for more information.",
            'account'
        );

        res.json({
            success: true,
            message: is_active ? 'User activated successfully' : 'User deactivated successfully',
            data: user
        });
    } catch (error) {
        console.error('User toggle error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to change user status'
        });
    }
});

// 7. Ban/unban user
app.post('/api/admin/users/:id/ban', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason, action } = req.body;
        let is_banned = true;
        let ban_reason = reason || 'Not specified';

        if (action == 'unban') {
            is_banned = false;
            ban_reason = null;
        }

        const { data: user, error } = await supabase
            .from('users')
            .update({
                is_banned: is_banned,
                ban_reason: ban_reason,
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .select()
            .single();

        if (error) {
            throw error;
        }

        // Send notification to user
        await sendNotification(
            id,
            is_banned ? "Account Banned" : "Account Unbanned",
            is_banned
                ? `Your account has been banned due to: ${ban_reason}. Please contact support for more information.`
                : "Your account has been unbanned. You can now use the platform again.",
            'account'
        );

        res.json({
            success: true,
            message: is_banned ? 'User banned successfully' : 'User unbanned successfully',
            data: user
        });
    } catch (error) {
        console.error('Ban/unban error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to ban/unban user'
        });
    }
});

// 8. Update user data
app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;

        // Only allowed fields
        const allowedUpdates = ['balance', 'total_earnings', 'full_name', 'email', 'referral_code'];
        const filteredUpdates = {};
        Object.keys(updates).forEach(key => {
            if (allowedUpdates.includes(key)) {
                filteredUpdates[key] = updates[key];
            }
        });
        filteredUpdates.updated_at = new Date().toISOString();

        const { data: user, error } = await supabase
            .from('users')
            .update(filteredUpdates)
            .eq('id', id)
            .select()
            .single();
        if (error) {
            throw error;
        }
        res.json({
            success: true,
            message: 'User data updated successfully',
            data: user
        });
    } catch (error) {
        console.error('User update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user data'
        });
    }
});

// 9. Get payments
app.get('/api/admin/payments', authenticateAdmin, async (req, res) => {
    try {
        const { status = 'pending', page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        let query = supabase
            .from('payments')
            .select('*, user:user_id(email, referral_code, is_active)', { count: 'exact' })
            .order('created_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (status != 'all') {
            query = query.eq('status', status);
        }

        const { data: payments, count, error } = await query;

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            data: {
                payments: payments || [],
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: count || 0,
                    total_pages: Math.ceil((count || 0) / limit)
                }
            }
        });
    } catch (error) {
        console.error('Payments load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load payments'
        });
    }
});

// 10. Approve payment
app.post('/api/admin/payments/:id/approve', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const admin = req.admin;

        // Get payment data
        const { data: payment, error: paymentError } = await supabase
            .from('payments')
            .select('*')
            .eq('id', id)
            .single();

        if (paymentError || !payment) {
            return res.status(404).json({
                success: false,
                message: 'Payment not found'
            });
        }

        if (payment.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: `Payment already ${payment.status}`
            });
        }

        // Get user data
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('id', payment.user_id)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if user is already active
        if (user.is_active) {
            return res.status(400).json({
                success: false,
                message: 'User is already active'
            });
        }

        // Update payment status
        await supabase
            .from("payments")
            .update({
                status: 'approved',
                verified_by: admin.id,
                verified_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .eq('id', id);

        // Add $1 to platform balance
        await addToPlatformBalance(payment.amount);

        // Activate user account
        await supabase
            .from("users")
            .update({
                is_active: true,
                updated_at: new Date().toISOString()
            })
            .eq('id', payment.user_id);

        // Log user activity
        await logUserActivity(
            payment.user_id,
            'payment_approved',
            'Payment approved and account activated',
            payment.amount,
            payment.transaction_id,
            req
        );

        // If there is a referrer, add commission
        if (user.referred_by) {
            const { data: referrer } = await supabase
                .from("users")
                .select("*")
                .eq('referral_code', user.referred_by)
                .single();

            if (referrer && referrer.is_active) {
                const commissionAmount = payment.amount * 0.5; // 50%
                const newBalance = (referrer.balance || 0) + commissionAmount;
                const newEarnings = (referrer.total_earnings || 0) + commissionAmount;

                // Update referrer balance
                await supabase
                    .from('users')
                    .update({
                        balance: newBalance,
                        total_earnings: newEarnings,
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', referrer.id);

                // Update referral record
                await supabase
                    .from('referrals')
                    .update({
                        status: 'active',
                        commission_amount: commissionAmount,
                        updated_at: new Date().toISOString()
                    })
                    .eq('referrer_id', referrer.id)
                    .eq('referred_id', user.id);

                // Log user activity
                await logUserActivity(
                    referrer.id,
                    'referral_commission',
                    `Commission earned from referral ${user.email}`,
                    commissionAmount,
                    payment.id,
                    req
                );

                // Send notification to referrer
                await sendNotification(
                    referrer.id,
                    'New Referral Commission',
                    `You have earned a commission of $${commissionAmount} from referral ${user.email}`,
                    'commission'
                );
            }
        }

        // Send notification to user
        await sendNotification(
            user.id,
            "Account Activated",
            "Your account has been activated successfully. You can now use all platform features.",
            'account'
        );

        res.json({
            success: true,
            message: 'Payment approved and user account activated'
        });
    } catch (error) {
        console.error('Payment approval error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve payment'
        });
    }
});

// 11. Reject payment
app.post('/api/admin/payments/:id/reject', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;

        if (!reason) {
            return res.status(400).json({
                success: false,
                message: 'Rejection reason is required'
            });
        }

        // Get payment data
        const { data: payment, error } = await supabase
            .from('payments')
            .select('*')
            .eq('id', id)
            .single();

        if (error || !payment) {
            return res.status(404).json({
                success: false,
                message: 'Payment not found'
            });
        }

        // Update payment status
        await supabase
            .from('payments')
            .update({
                status: 'rejected',
                rejection_reason: reason,
                updated_at: new Date().toISOString()
            })
            .eq('id', id);

        // Log user activity
        await logUserActivity(
            payment.user_id,
            'payment_rejected',
            `Payment rejected: ${reason}`,
            0,
            payment.transaction_id,
            req
        );

        // Send notification to user
        await sendNotification(
            payment.user_id,
            'Payment Rejected',
            `Your payment has been rejected due to: ${reason}. Please check and try again.`,
            'payment'
        );

        res.json({
            success: true,
            message: 'Payment rejected successfully'
        });
    } catch (error) {
        console.error('Payment rejection error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject payment'
        });
    }
});

// 12. Get withdrawals
app.get('/api/admin/withdrawals', authenticateAdmin, async (req, res) => {
    try {
        const { status = 'pending', page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;

        let query = supabase
            .from('withdrawals')
            .select('*, user:user_id(email, balance)', { count: 'exact' })
            .order('created_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (status !== 'all') {
            query = query.eq('status', status);
        }

        const { data: withdrawals, count, error } = await query;

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            data: {
                withdrawals: withdrawals || [],
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: count || 0,
                    total_pages: Math.ceil((count || 0) / limit)
                }
            }
        });
    } catch (error) {
        console.error('Withdrawals load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load withdrawals'
        });
    }
});

// 13. Approve withdrawal
app.post('/api/admin/withdrawals/:id/approve', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const { data: withdrawal, error } = await supabase
            .from('withdrawals')
            .select('*')
            .eq('id', id)
            .single();

        if (error || !withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found'
            });
        }

        if (withdrawal.status !== 'pending') {
            return res.status(400).json({
                success: false,
                message: `Withdrawal already ${withdrawal.status}`
            });
        }

        // Subtract from platform balance
        const currentBalance = parseFloat(await getSetting('platform_balance', '0'));
        const newBalance = currentBalance - withdrawal.amount;
        await updateSetting('platform_balance', newBalance.toString());

        // Log user activity
        await logUserActivity(
            withdrawal.user_id,
            'withdrawal_approved',
            'Withdrawal approved and processed',
            withdrawal.amount,
            withdrawal.id,
            req
        );

        // Send notification to user
        await sendNotification(
            withdrawal.user_id,
            "Withdrawal Approved",
            `Amount ${withdrawal.amount} has been transferred to your wallet.`,
            'withdrawal'
        );

        // Delete the withdrawal request after processing
        await supabase
            .from('withdrawals')
            .delete()
            .eq('id', id);

        res.json({
            success: true,
            message: 'Withdrawal approved and deleted successfully'
        });
    } catch (error) {
        console.error('Withdrawal approval error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve withdrawal'
        });
    }
});

// 14. Reject withdrawal
app.post('/api/admin/withdrawals/:id/reject', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;

        if (!reason) {
            return res.status(400).json({
                success: false,
                message: 'Rejection reason is required'
            });
        }

        // Get withdrawal data
        const { data: withdrawal, error: withdrawalError } = await supabase
            .from('withdrawals')
            .select('*')
            .eq('id', id)
            .single();

        if (withdrawalError || !withdrawal) {
            return res.status(404).json({
                success: false,
                message: 'Withdrawal not found'
            });
        }

        // Get user data
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('balance')
            .eq('id', withdrawal.user_id)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Return amount to user
        const newBalance = (user.balance || 0) + withdrawal.amount;
        await supabase
            .from('users')
            .update({
                balance: newBalance,
                updated_at: new Date().toISOString()
            })
            .eq('id', withdrawal.user_id);

        // Log user activity
        await logUserActivity(
            withdrawal.user_id,
            'withdrawal_rejected',
            `Withdrawal rejected: ${reason}. Amount returned to balance.`,
            withdrawal.amount,
            withdrawal.id,
            req
        );

        // Send notification to user
        await sendNotification(
            withdrawal.user_id,
            "Withdrawal Rejected",
            `Your withdrawal of ${withdrawal.amount} has been rejected due to: ${reason}. The amount has been returned to your balance.`,
            'withdrawal'
        );

        // Delete the withdrawal request
        await supabase
            .from('withdrawals')
            .delete()
            .eq('id', id);

        res.json({
            success: true,
            message: 'Withdrawal rejected and deleted successfully'
        });
    } catch (error) {
        console.error('Withdrawal rejection error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reject withdrawal'
        });
    }
});

// 15. Get games (admin)
app.get('/api/admin/games', authenticateAdmin, async (req, res) => {
    try {
        const { data: games, error } = await supabase
            .from('game_links')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            data: games || []
        });
    } catch (error) {
        console.error('Games load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load games'
        });
    }
});

// 16. Add game
app.post('/api/admin/games', authenticateAdmin, async (req, res) => {
    try {
        const { title, description, game_url, thumbnail_url, game_type, access_type } = req.body;

        if (!title || !game_url) {
            return res.status(400).json({
                success: false,
                message: 'Title and game URL are required'
            });
        }

        const { data: game, error } = await supabase
            .from('game_links')
            .insert({
                title: title,
                description: description || "",
                game_url: game_url,
                thumbnail_url: thumbnail_url || null,
                game_type: game_type || 'casino',
                access_type: access_type || 'free',
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            })
            .select()
            .single();

        if (error) {
            throw error;
        }
        res.json({
            success: true,
            message: 'Game added successfully',
            data: game
        });
    } catch (error) {
        console.error('Game add error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add game'
        });
    }
});

// 17. Update game
app.put('/api/admin/games/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;

        const { data: game, error } = await supabase
            .from('game_links')
            .update({ ...updates, updated_at: new Date().toISOString() })
            .eq('id', id)
            .select()
            .single();

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'Game updated successfully',
            data: game
        });
    } catch (error) {
        console.error('Game update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update game'
        });
    }
});

// 18. Delete game
app.delete('/api/admin/games/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const { error } = await supabase
            .from('game_links')
            .delete()
            .eq('id', id);

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'Game deleted successfully'
        });
    } catch (error) {
        console.error('Game delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete game'
        });
    }
});

// 19. Get contests (admin)
app.get('/api/admin/contests', authenticateAdmin, async (req, res) => {
    try {
        const { data: contests, error } = await supabase
            .from('contests')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }

        // Get participations count for each contest
        if (contests) {
            for (let contest of contests) {
                const { count } = await supabase
                    .from('contest_participations')
                    .select('*', { count: 'exact', head: true })
                    .eq('contest_id', contest.id);

                contest.participants_count = count || 0;
                contest.total_revenue = contest.ticket_price * contest.participants_count;
            }
        }

        res.json({
            success: true,
            data: contests || []
        });
    } catch (error) {
        console.error('Contests load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load contests'
        });
    }
});

// 20. Add contest
app.post('/api/admin/contests', authenticateAdmin, async (req, res) => {
    try {
        const {
            title,
            description,
            ticket_price,
            prize_amount,
            status,
            end_date,
            max_participants,
            max_tickets_per_user,
            auto_draw_number
        } = req.body;

        if (!title || !ticket_price || !prize_amount || !max_participants) {
            return res.status(400).json({
                success: false,
                message: 'Title, ticket price, prize amount, and max participants are required'
            });
        }

        const { data: contest, error } = await supabase
            .from('contests')
            .insert({
                title: title,
                description: description || "",
                ticket_price: parseFloat(ticket_price),
                prize_amount: parseFloat(prize_amount),
                status: status || 'active',
                max_participants: parseInt(max_participants) || 100,
                max_tickets_per_user: parseInt(max_tickets_per_user) || 5,
                auto_draw_number: auto_draw_number || false,
                winning_number: null,
                start_date: new Date().toISOString(),
                end_date: end_date || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
                created_at: new Date().toISOString()
            })
            .select()
            .single();

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'Contest added successfully',
            data: contest
        });
    } catch (error) {
        console.error('Contest add error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add contest'
        });
    }
});

// 21. Update contest
app.put('/api/admin/contests/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;

        const { data: contest, error } = await supabase
            .from('contests')
            .update({
                ...updates,
                updated_at: new Date().toISOString()
            })
            .eq('id', id)
            .select()
            .single();

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'Contest updated successfully',
            data: contest
        });
    } catch (error) {
        console.error('Contest update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update contest'
        });
    }
});

// 22. Delete contest
app.delete('/api/admin/contests/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Delete participations first
        await supabase
            .from('contest_participations')
            .delete()
            .eq('contest_id', id);

        // Delete contest
        const { error } = await supabase
            .from('contests')
            .delete()
            .eq('id', id);

        if (error) {
            throw error;
        }

        res.json({
            success: true,
            message: 'Contest deleted successfully'
        });
    } catch (error) {
        console.error('Contest delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete contest'
        });
    }
});

// 23. Draw contest winner
app.post('/api/admin/contests/:id/draw', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { winning_number } = req.body;

        // Get contest
        const { data: contest, error: contestError } = await supabase
            .from('contests')
            .select('*')
            .eq('id', id)
            .single();

        if (contestError || !contest) {
            return res.status(404).json({
                success: false,
                message: 'Contest not found'
            });
        }

        // Get all participations
        const { data: participations, error: partError } = await supabase
            .from('contest_participations')
            .select('*, user:user_id(email, balance)')
            .eq('contest_id', id);

        if (partError) {
            throw partError;
        }

        if (!participations || participations.length == 0) {
            return res.status(400).json({
                success: false,
                message: 'No participants for this contest'
            });
        }

        // Determine winning number
        let finalWinningNumber;
        if (contest.auto_draw_number && winning_number) {
            finalWinningNumber = parseInt(winning_number);
        } else {
            finalWinningNumber = Math.floor(Math.random() * contest.max_participants) + 1;
        }

        // Find winner by ticket number
        let winner = null;
        for (const participation of participations) {
            if (participation.ticket_number == finalWinningNumber) {
                winner = participation;
                break;
            }
        }

        // If no exact match, pick random
        if (!winner) {
            winner = participations[Math.floor(Math.random() * participations.length)];
        }

        // Update contest with winner and winning number
        await supabase
            .from('contests')
            .update({
                winner_id: winner.user_id,
                winner_email: winner.user.email,
                winning_number: finalWinningNumber,
                drawn_at: new Date().toISOString(),
                status: 'completed',
                updated_at: new Date().toISOString()
            })
            .eq('id', id);

        // Add prize to winner's balance
        const newBalance = (winner.user.balance || 0) + contest.prize_amount;
        await supabase
            .from('users')
            .update({
                balance: newBalance,
                total_earnings: (winner.user.total_earnings || 0) + contest.prize_amount,
                updated_at: new Date().toISOString()
            })
            .eq('id', winner.user_id);

        // Log user activity
        await logUserActivity(
            winner.user_id,
            'contest_won',
            `Won contest "${contest.title}"`,
            contest.prize_amount,
            contest.id,
            req
        );

        // Send notification to winner
        await sendNotification(
            winner.user_id,
            "Contest Winner!",
            `Congratulations! You won $${contest.prize_amount} in the "${contest.title}" contest! Winning number was ${finalWinningNumber} and your ticket was ${winner.ticket_number}.`,
            'contest'
        );

        // Send notifications to all participants
        for (const participation of participations) {
            if (participation.user_id !== winner.user_id) {
                await sendNotification(
                    participation.user_id,
                    "Contest Results",
                    `The contest "${contest.title}" has ended. Winning number was ${finalWinningNumber}. Better luck next time!`,
                    'contest'
                );
            }
        }

        res.json({
            success: true,
            message: 'winner drawn successfully',
            data: {
                contest_id: contest.id,
                winning_number: finalWinningNumber,
                winner: {
                    user_id: winner.user_id,
                    email: winner.user.email,
                    ticket_number: winner.ticket_number,
                    prize_amount: contest.prize_amount
                },
                total_participants: participations.length
            }
        });
    } catch (error) {
        console.error('Contest draw error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to draw contest winner'
        });
    }
});

// 24. Get settings
app.get('/api/admin/settings', authenticateAdmin, async (req, res) => {
    try {
        const { data: settings, error } = await supabase
            .from('settings')
            .select('*')
            .order('key', { ascending: true });

        if (error) {
            throw error;
        }

        // Convert to object
        const settingsObj = {};
        settings.forEach(setting => {
            settingsObj[setting.key] = setting.value;
        });

        res.json({
            success: true,
            data: settingsObj
        });
    } catch (error) {
        console.error('Settings load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load settings'
        });
    }
});

// 25. Update settings
app.post('/api/admin/settings', authenticateAdmin, async (req, res) => {
    try {
        const settings = req.body;

        for (const [key, value] of Object.entries(settings)) {
            await updateSetting(key, value);
        }

        res.json({
            success: true,
            message: 'Settings updated successfully'
        });
    } catch (error) {
        console.error('Settings update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update settings'
        });
    }
});

// 26. Change admin password
app.post('/api/admin/change-password', authenticateAdmin, async (req, res) => {
    try {
        const { new_password } = req.body;
        const admin = req.admin;

        if (!new_password || new_password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters'
            });
        }

        const hashedPassword = await bcrypt.hash(new_password, 10);

        await supabase
            .from('users')
            .update({
                password: hashedPassword,
                updated_at: new Date().toISOString()
            })
            .eq('id', admin.id);

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to change password'
        });
    }
});

// 27. Send notification to users
app.post('/api/admin/send-notification', authenticateAdmin, async (req, res) => {
    try {
        const { user_id, title, message, type, send_to_all } = req.body;

        if (!title || !message) {
            return res.status(400).json({
                success: false,
                message: 'Title and message are required'
            });
        }

        if (send_to_all) {
            // Send to all active users
            const { data: users, error } = await supabase
                .from('users')
                .select('id')
                .eq('is_active', true)
                .eq('is_banned', false);

            if (users && users.length > 0) {
                for (const user of users) {
                    await sendNotification(
                        user.id,
                        title,
                        message,
                        type || 'system'
                    );
                }
            }

            res.json({
                success: true,
                message: `Notification sent to all ${users?.length || 0} active users`
            });
        } else if (user_id) {
            // Send to specific user
            await sendNotification(
                user_id,
                title,
                message,
                type || 'system'
            );

            res.json({
                success: true,
                message: 'Notification sent to user'
            });
        } else {
            return res.status(400).json({
                success: false,
                message: 'Either user_id or send_to_all is required'
            });
        }
    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send notification'
        });
    }
});

// ======================= PAGES MANAGEMENT ==============================

// 28. Get page content
app.get('/api/page/:slug', async (req, res) => {
    try {
        const { slug } = req.params;

        const { data: page, error } = await supabase
            .from('pages')
            .select('*')
            .eq('slug', slug)
            .single();

        if (error || !page) {
            return res.status(404).json({
                success: false,
                message: 'Page not found'
            });
        }

        res.json({
            success: true,
            data: page
        });
    } catch (error) {
        console.error('Page load error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load page'
        });
    }
});

// 29. Update page (Admin only)
app.post('/api/admin/page/:slug', authenticateAdmin, async (req, res) => {
    try {
        const { slug } = req.params;
        const { title, content } = req.body;

        if (!title || !content) {
            return res.status(400).json({
                success: false,
                message: 'Title and content are required'
            });
        }

        // Check if page exists
        const { data: existingPage } = await supabase
            .from('pages')
            .select('*')
            .eq('slug', slug)
            .single();

        if (existingPage) {
            // Update existing page
            await supabase
                .from('pages')
                .update({
                    title,
                    content,
                    updated_at: new Date().toISOString()
                })
                .eq('slug', slug);
        } else {
            // Create new page
            await supabase
                .from('pages')
                .insert({
                    slug,
                    title,
                    content,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                });
        }

        res.json({
            success: true,
            message: 'Page saved successfully'
        });
    } catch (error) {
        console.error('Page save error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save page'
        });
    }
});

// 30. View public privacy page
app.get('/privacy', async (req, res) => {
    try {
        const { data: page } = await supabase
            .from('pages')
            .select('*')
            .eq('slug', 'privacy')
            .single();

        if (!page) {
            return res.redirect('/');
        }

        res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${page.title} - ZEMA</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
        }
        .logo {
            font-size: 2.5em;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .content {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 15px;
            line-height: 1.8;
        }
        .content h1 { color: #667eea; margin-bottom: 20px; }
        .content h2 { color: #764ba2; margin: 30px 0 15px 0; }
        .content p { margin-bottom: 15px; color: #555; }
        .content ul, .content ol { margin-left: 20px; margin-bottom: 15px; }
        .back-btn {
            display: inline-block;
            margin-top: 30px;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">ZEMA</div>
            <h1>${page.title}</h1>
            <a href="/" class="back-btn">← Back to Home</a>
        </div>
        <div class="content">
            ${page.content}
        </div>
    </div>
</body>
</html>
        `);
    } catch (error) {
        res.redirect('/');
    }
});

// 31. View public terms page
app.get('/terms', async (req, res) => {
    try {
        const { data: page } = await supabase
            .from('pages')
            .select('*')
            .eq('slug', 'terms')
            .single();

        if (!page) {
            return res.redirect('/');
        }

        res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${page.title} - ZEMA</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
        }
        .logo {
            font-size: 2.5em;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .content {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 15px;
            line-height: 1.8;
        }
        .content h1 { color: #667eea; margin-bottom: 20px; }
        .content h2 { color: #764ba2; margin: 30px 0 15px 0; }
        .content p { margin-bottom: 15px; color: #555; }
        .content ul, .content ol { margin-left: 20px; margin-bottom: 15px; }
        .back-btn {
            display: inline-block;
            margin-top: 30px;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">ZEMA</div>
            <h1>${page.title}</h1>
            <a href="/" class="back-btn">← Back to Home</a>
        </div>
        <div class="content">
            ${page.content}
        </div>
    </div>
</body>
</html>
        `);
    } catch (error) {
        res.redirect('/');
    }
});

// ================= VIEW ROUTES ================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/llovezeze', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 404
app.use((req, res) => {
    const filePath = path.join(__dirname, 'public', '404.html');
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).json({
                success: false,
                message: 'Page not found'
            });
        }
        res.status(404).sendFile(filePath);
    });
});

// 500
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// =============================== START SERVER ================================

const startServer = async () => {
    try {
        console.log("\n" + '='.repeat(60));
        console.log('ZEMA Platform - Final Version v3.1.0');
        console.log('='.repeat(60));

        // Initialize database
        const dbInitialized = await initializeDatabase();
        if (!dbInitialized) {
            console.error('Database initialization failed');
            process.exit(1);
        }

        // Start server
        app.listen(PORT, () => {
            console.log(`✓ Server running on: http://localhost:${PORT}`);
            console.log(`✓ Admin panel: http://localhost:${PORT}/admin`);
            console.log('='.repeat(60));
            console.log('Server ready to accept connections');
            console.log('='.repeat(60) + '\n');
        });
    } catch (error) {
        console.error('Server startup failed:', error);
        process.exit(1);
    }
};

startServer();
