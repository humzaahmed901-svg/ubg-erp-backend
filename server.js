// server.js
import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import compression from "compression";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import path from "path";
import { fileURLToPath } from "url";
import { z } from "zod";

dotenv.config();

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);

if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const pool = new Pool({
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT || 5432),
    database: process.env.PGDATABASE,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    max: 10
});

const COOKIE = "ubg_token";

const METHODS = [
    "HBL",
    "Meezan Bank",
    "UBL",
    "MCB Bank",
    "Bank Alfalah",
    "Allied Bank",
    "Bank Al Habib",
    "Askari Bank",
    "Faysal Bank",
    "Standard Chartered Pakistan",
    "National Bank of Pakistan",
    "JS Bank",
    "Soneri Bank",
    "Habib Metropolitan Bank",
    "Dubai Islamic Bank Pakistan",
    "Easypaisa",
    "JazzCash",
    "SadaPay",
    "NayaPay",
    "Card / POS",
    "Visa",
    "Mastercard",
    "UnionPay",
    "Bank Transfer",
    "IBFT",
    "Raast",
    "Cheque"
];

const loginLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many login attempts. Try again later."
    }
});

const ok = (res, data = {}) =>
    res.json({
        success: true,
        ...data
    });

const fail = (res, status, message) =>
    res.status(status).json({
        success: false,
        message
    });

const q = (text, params = []) =>
    pool.query(text, params);

const money = n =>
    Math.round(Number(n || 0) * 100) / 100;

const asyncRoute = fn =>
    (req, res, next) =>
        Promise.resolve(
            fn(req, res, next)
        ).catch(next);


/* =========================================================
   DATABASE
   ========================================================= */

async function initDB() {

    await q(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'admin'
                CHECK(role IN ('admin','staff')),
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS articles (
            id BIGSERIAL PRIMARY KEY,
            article_name VARCHAR(160) NOT NULL,
            article_code VARCHAR(100) UNIQUE NOT NULL,
            size VARCHAR(50),
            colour VARCHAR(80),
            quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity >= 0),
            purchase_price NUMERIC(12,2) NOT NULL DEFAULT 0,
            sale_price NUMERIC(12,2) NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS customers (
            id BIGSERIAL PRIMARY KEY,
            name VARCHAR(160) NOT NULL,
            mobile VARCHAR(40),
            province VARCHAR(80),
            address TEXT,
            ntn_strn VARCHAR(100),
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS suppliers (
            id BIGSERIAL PRIMARY KEY,
            name VARCHAR(160) NOT NULL,
            mobile VARCHAR(40),
            province VARCHAR(80),
            address TEXT,
            ntn_strn VARCHAR(100),
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS purchases (
            id BIGSERIAL PRIMARY KEY,

            article_id BIGINT
                REFERENCES articles(id)
                ON DELETE SET NULL,

            /* Article snapshot */
            article_name VARCHAR(160),
            article_code VARCHAR(100),
            size VARCHAR(50),
            colour VARCHAR(80),

            quantity INTEGER NOT NULL
                CHECK(quantity > 0),

            purchase_price NUMERIC(12,2)
                NOT NULL DEFAULT 0,

            supplier_id BIGINT
                REFERENCES suppliers(id)
                ON DELETE SET NULL,

            supplier_name VARCHAR(160),

            created_by BIGINT
                REFERENCES users(id)
                ON DELETE SET NULL,

            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS sales (
            id BIGSERIAL PRIMARY KEY,

            invoice_no VARCHAR(60)
                UNIQUE NOT NULL,

            customer_id BIGINT
                REFERENCES customers(id)
                ON DELETE SET NULL,

            customer_name VARCHAR(160),
            mobile VARCHAR(40),
            province VARCHAR(80),
            address TEXT,

            payment_type VARCHAR(20) NOT NULL
                CHECK(payment_type IN ('Cash','Online')),

            online_method VARCHAR(80),

            subtotal NUMERIC(12,2) DEFAULT 0,
            tax_percent NUMERIC(5,2) DEFAULT 0,
            tax_amount NUMERIC(12,2) DEFAULT 0,
            grand_total NUMERIC(12,2) DEFAULT 0,
            paid_amount NUMERIC(12,2) DEFAULT 0,
            balance NUMERIC(12,2) DEFAULT 0,

            created_by BIGINT
                REFERENCES users(id)
                ON DELETE SET NULL,

            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS sale_items (
            id BIGSERIAL PRIMARY KEY,

            sale_id BIGINT NOT NULL
                REFERENCES sales(id)
                ON DELETE CASCADE,

            article_id BIGINT
                REFERENCES articles(id)
                ON DELETE SET NULL,

            /* Article snapshot */
            article_name VARCHAR(160) NOT NULL,
            article_code VARCHAR(100) NOT NULL,
            size VARCHAR(50),
            colour VARCHAR(80),

            quantity INTEGER NOT NULL
                CHECK(quantity > 0),

            rate NUMERIC(12,2) NOT NULL,
            line_total NUMERIC(12,2) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payments (
            id BIGSERIAL PRIMARY KEY,

            sale_id BIGINT
                REFERENCES sales(id)
                ON DELETE SET NULL,

            customer_name VARCHAR(160),

            amount NUMERIC(12,2)
                NOT NULL CHECK(amount > 0),

            payment_type VARCHAR(20) NOT NULL,
            method VARCHAR(80),

            reference_no VARCHAR(120),
            bank_name VARCHAR(160),
            cheque_no VARCHAR(100),

            status VARCHAR(30)
                DEFAULT 'Completed',

            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        ALTER TABLE payments
            ADD COLUMN IF NOT EXISTS reference_no VARCHAR(120),
            ADD COLUMN IF NOT EXISTS bank_name VARCHAR(160),
            ADD COLUMN IF NOT EXISTS cheque_no VARCHAR(100),
            ADD COLUMN IF NOT EXISTS status VARCHAR(30)
                DEFAULT 'Completed';

        CREATE INDEX IF NOT EXISTS idx_articles_code
            ON articles(article_code);

        CREATE INDEX IF NOT EXISTS idx_sales_date
            ON sales(created_at);

        CREATE INDEX IF NOT EXISTS idx_payments_date
            ON payments(created_at);
    `);


    /* =====================================================
       ARTICLE DELETE / HISTORY MIGRATION
       ===================================================== */

    /*
       Purchase history ke liye article snapshot columns.
    */

    await q(`
        ALTER TABLE purchases
        ADD COLUMN IF NOT EXISTS article_name VARCHAR(160),
        ADD COLUMN IF NOT EXISTS article_code VARCHAR(100),
        ADD COLUMN IF NOT EXISTS size VARCHAR(50),
        ADD COLUMN IF NOT EXISTS colour VARCHAR(80)
    `);


    /*
       Existing purchases ke article details ko snapshot
       columns mein copy karo.
    */

    await q(`
        UPDATE purchases p
        SET
            article_name = a.article_name,
            article_code = a.article_code,
            size = a.size,
            colour = a.colour
        FROM articles a
        WHERE p.article_id = a.id
          AND (
              p.article_name IS NULL
              OR p.article_code IS NULL
          )
    `);


    /*
       purchases article foreign key ko
       ON DELETE SET NULL karo.
    */

    await q(`
        ALTER TABLE purchases
        DROP CONSTRAINT IF EXISTS purchases_article_id_fkey
    `);

    await q(`
        ALTER TABLE purchases
        ALTER COLUMN article_id DROP NOT NULL
    `);

    await q(`
        ALTER TABLE purchases
        ADD CONSTRAINT purchases_article_id_fkey
        FOREIGN KEY (article_id)
        REFERENCES articles(id)
        ON DELETE SET NULL
    `);


    /*
       sale_items article foreign key ko bhi
       ON DELETE SET NULL karo.
       Sale item mein article snapshot already stored hai.
    */

    await q(`
        ALTER TABLE sale_items
        DROP CONSTRAINT IF EXISTS sale_items_article_id_fkey
    `);

    await q(`
        ALTER TABLE sale_items
        ALTER COLUMN article_id DROP NOT NULL
    `);

    await q(`
        ALTER TABLE sale_items
        ADD CONSTRAINT sale_items_article_id_fkey
        FOREIGN KEY (article_id)
        REFERENCES articles(id)
        ON DELETE SET NULL
    `);


    await ensureAdmin();
}


async function ensureAdmin() {

    const admin = await q(
        `SELECT id FROM users WHERE role='admin' LIMIT 1`
    );

    if (admin.rowCount) return;

    const username = process.env.ADMIN_USERNAME;
    const password = process.env.ADMIN_PASSWORD;

    if (!username || !password) {
        console.log(
            "No admin bootstrap credentials supplied."
        );
        return;
    }

    const hash =
        await bcrypt.hash(password, 12);

    await q(
        `INSERT INTO users
         (username,password_hash,role)
         VALUES($1,$2,'admin')
         ON CONFLICT(username) DO NOTHING`,
        [username, hash]
    );

    console.log(
        `Admin bootstrap checked: ${username}`
    );
}


/* =========================================================
   AUTH
   ========================================================= */

function tokenFor(user) {

    return jwt.sign(
        {
            id: user.id,
            username: user.username,
            role: user.role
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "8h"
        }
    );
}


function auth(req, res, next) {

    const token = req.cookies[COOKIE];

    if (!token) {
        return fail(
            res,
            401,
            "Authentication required."
        );
    }

    try {

        req.user = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        next();

    } catch {

        res.clearCookie(
            COOKIE,
            {
                path: "/"
            }
        );

        return fail(
            res,
            401,
            "Invalid or expired session."
        );
    }
}


function validatePayment(p) {

    if (!p) return null;

    if (!["Cash", "Online"].includes(
        p.payment_type
    )) {
        throw new Error(
            "Invalid payment type."
        );
    }

    if (!p.amount || Number(p.amount) <= 0) {
        throw new Error(
            "Payment amount must be greater than zero."
        );
    }

    if (p.payment_type === "Cash") {

        return {
            payment_type: "Cash",
            method: "Cash",
            amount: money(p.amount)
        };
    }

    if (!METHODS.includes(p.method)) {
        throw new Error(
            "Invalid online payment method."
        );
    }

    if (
        ["Bank Transfer", "IBFT", "Cheque"]
            .includes(p.method) &&
        !String(p.bank_name || "").trim()
    ) {
        throw new Error(
            "Bank name is required."
        );
    }

    if (
        !String(p.reference_no || "").trim() &&
        p.method !== "Cheque"
    ) {
        throw new Error(
            "Reference number is required."
        );
    }

    if (
        p.method === "Cheque" &&
        !String(p.cheque_no || "").trim()
    ) {
        throw new Error(
            "Cheque number is required."
        );
    }

    return {
        payment_type: "Online",
        method: p.method,
        amount: money(p.amount),
        reference_no:
            String(p.reference_no || "").trim(),
        bank_name:
            String(p.bank_name || "").trim(),
        cheque_no:
            String(p.cheque_no || "").trim()
    };
}


/* =========================================================
   HEALTH
   ========================================================= */

app.get(
    "/api/health",
    (_, res) =>
        ok(res, {
            status: "ok",
            service: "U&BG ERP ONLINE"
        })
);


app.get(
    "/api/db-test",
    auth,
    asyncRoute(async (_, res) => {

        await q("SELECT 1");

        ok(res, {
            status: "connected"
        });
    })
);


/* =========================================================
   AUTH ROUTES
   ========================================================= */

app.post(
    "/api/auth/login",
    loginLimit,
    asyncRoute(async (req, res) => {

        const username =
            String(
                req.body.username || ""
            ).trim();

        const password =
            String(
                req.body.password || ""
            );

        if (!username || !password) {
            return fail(
                res,
                400,
                "Username and password are required."
            );
        }

        const result = await q(
            `SELECT
                id,
                username,
                password_hash,
                role
             FROM users
             WHERE username=$1`,
            [username]
        );

        if (!result.rowCount) {
            return fail(
                res,
                401,
                "Invalid username or password."
            );
        }

        const user = result.rows[0];

        const valid =
            await bcrypt.compare(
                password,
                user.password_hash
            );

        if (!valid) {
            return fail(
                res,
                401,
                "Invalid username or password."
            );
        }

        const token =
            tokenFor(user);

        res.cookie(
            COOKIE,
            token,
            {
                httpOnly: true,
                secure:
                    process.env.NODE_ENV ===
                    "production",
                sameSite: "lax",
                maxAge:
                    8 * 60 * 60 * 1000,
                path: "/"
            }
        );

        ok(res, {
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });
    })
);


app.get(
    "/api/auth/me",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(
            `SELECT
                id,
                username,
                role
             FROM users
             WHERE id=$1`,
            [req.user.id]
        );

        if (!r.rowCount) {
            return fail(
                res,
                401,
                "User no longer exists."
            );
        }

        ok(res, {
            user: r.rows[0]
        });
    })
);


app.post(
    "/api/auth/logout",
    auth,
    asyncRoute(async (_, res) => {

        res.clearCookie(
            COOKIE,
            {
                path: "/"
            }
        );

        ok(res, {
            message: "Logged out."
        });
    })
);


app.post(
    "/api/auth/change-password",
    auth,
    asyncRoute(async (req, res) => {

        const current =
            String(
                req.body.currentPassword || ""
            );

        const next =
            String(
                req.body.newPassword || ""
            );

        if (!current || next.length < 8) {
            return fail(
                res,
                400,
                "Invalid password."
            );
        }

        const r = await q(
            `SELECT password_hash
             FROM users
             WHERE id=$1`,
            [req.user.id]
        );

        if (!r.rowCount) {
            return fail(
                res,
                404,
                "User not found."
            );
        }

        if (
            !await bcrypt.compare(
                current,
                r.rows[0].password_hash
            )
        ) {
            return fail(
                res,
                400,
                "Current password is incorrect."
            );
        }

        const hash =
            await bcrypt.hash(next, 12);

        await q(
            `UPDATE users
             SET password_hash=$1
             WHERE id=$2`,
            [hash, req.user.id]
        );

        ok(res, {
            message:
                "Password changed successfully."
        });
    })
);


/* =========================================================
   ARTICLES
   ========================================================= */

app.get(
    "/api/articles",
    auth,
    asyncRoute(async (_, res) => {

        const r = await q(`
            SELECT *
            FROM articles
            ORDER BY id DESC
        `);

        ok(res, {
            articles: r.rows
        });
    })
);


app.post(
    "/api/articles",
    auth,
    asyncRoute(async (req, res) => {

        const {
            article_name,
            article_code,
            size,
            colour,
            quantity,
            purchase_price,
            sale_price
        } = req.body;

        if (!article_name || !article_code) {
            return fail(
                res,
                400,
                "Article name and code are required."
            );
        }

        const r = await q(`
            INSERT INTO articles
            (
                article_name,
                article_code,
                size,
                colour,
                quantity,
                purchase_price,
                sale_price
            )
            VALUES($1,$2,$3,$4,$5,$6,$7)
            RETURNING *
        `, [
            String(article_name).trim(),
            String(article_code).trim(),
            size || null,
            colour || null,
            Number(quantity || 0),
            money(purchase_price),
            money(sale_price)
        ]);

        ok(res, {
            article: r.rows[0]
        });
    })
);


app.put(
    "/api/articles/:id",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(`
            UPDATE articles
            SET
                article_name=$1,
                article_code=$2,
                size=$3,
                colour=$4,
                quantity=$5,
                purchase_price=$6,
                sale_price=$7
            WHERE id=$8
            RETURNING *
        `, [
            String(
                req.body.article_name || ""
            ).trim(),

            String(
                req.body.article_code || ""
            ).trim(),

            req.body.size || null,
            req.body.colour || null,

            Math.max(
                0,
                Number(req.body.quantity || 0)
            ),

            money(
                req.body.purchase_price
            ),

            money(
                req.body.sale_price
            ),

            req.params.id
        ]);

        if (!r.rowCount) {
            return fail(
                res,
                404,
                "Article not found."
            );
        }

        ok(res, {
            article: r.rows[0]
        });
    })
);


/*
   IMPORTANT:
   Article ab permanently delete ho sakta hai.
   Purchase aur Sale history foreign key ki wajah
   se delete nahi hogi.
*/

app.delete(
    "/api/articles/:id",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(`
            DELETE FROM articles
            WHERE id=$1
            RETURNING id
        `, [
            req.params.id
        ]);

        if (!r.rowCount) {
            return fail(
                res,
                404,
                "Article not found."
            );
        }

        ok(res, {
            message:
                "Article deleted successfully."
        });
    })
);


/* =========================================================
   INVENTORY
   ========================================================= */

app.get(
    "/api/inventory",
    auth,
    asyncRoute(async (_, res) => {

        const r = await q(`
            SELECT *,
                quantity * purchase_price
                    AS stock_value
            FROM articles
            ORDER BY article_name
        `);

        ok(res, {
            inventory: r.rows
        });
    })
);


/* =========================================================
   CUSTOMERS
   ========================================================= */

app.get(
    "/api/customers",
    auth,
    asyncRoute(async (_, res) => {

        const r = await q(
            `SELECT *
             FROM customers
             ORDER BY name`
        );

        ok(res, {
            customers: r.rows
        });
    })
);


app.post(
    "/api/customers",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(`
            INSERT INTO customers
            (
                name,
                mobile,
                province,
                address,
                ntn_strn
            )
            VALUES($1,$2,$3,$4,$5)
            RETURNING *
        `, [
            String(
                req.body.name || ""
            ).trim(),

            req.body.mobile || null,
            req.body.province || null,
            req.body.address || null,
            req.body.ntn_strn || null
        ]);

        ok(res, {
            customer: r.rows[0]
        });
    })
);


app.put(
    "/api/customers/:id",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(`
            UPDATE customers
            SET
                name=$1,
                mobile=$2,
                province=$3,
                address=$4,
                ntn_strn=$5
            WHERE id=$6
            RETURNING *
        `, [
            String(
                req.body.name || ""
            ).trim(),

            req.body.mobile || null,
            req.body.province || null,
            req.body.address || null,
            req.body.ntn_strn || null,
            req.params.id
        ]);

        if (!r.rowCount) {
            return fail(
                res,
                404,
                "Customer not found."
            );
        }

        ok(res, {
            customer: r.rows[0]
        });
    })
);


app.delete(
    "/api/customers/:id",
    auth,
    asyncRoute(async (req, res) => {

        const open = await q(`
            SELECT 1
            FROM sales
            WHERE customer_id=$1
              AND balance>0
            LIMIT 1
        `, [
            req.params.id
        ]);

        if (open.rowCount) {
            return fail(
                res,
                409,
                "Customer has pending balance and cannot be deleted."
            );
        }

        const r = await q(
            `DELETE FROM customers
             WHERE id=$1
             RETURNING id`,
            [req.params.id]
        );

        if (!r.rowCount) {
            return fail(
                res,
                404,
                "Customer not found."
            );
        }

        ok(res, {
            message: "Customer deleted."
        });
    })
);


/* =========================================================
   SUPPLIERS
   ========================================================= */

app.get(
    "/api/suppliers",
    auth,
    asyncRoute(async (_, res) => {

        const r = await q(
            `SELECT *
             FROM suppliers
             ORDER BY name`
        );

        ok(res, {
            suppliers: r.rows
        });
    })
);


app.post(
    "/api/suppliers",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(`
            INSERT INTO suppliers
            (
                name,
                mobile,
                province,
                address,
                ntn_strn
            )
            VALUES($1,$2,$3,$4,$5)
            RETURNING *
        `, [
            String(
                req.body.name || ""
            ).trim(),

            req.body.mobile || null,
            req.body.province || null,
            req.body.address || null,
            req.body.ntn_strn || null
        ]);

        ok(res, {
            supplier: r.rows[0]
        });
    })
);


app.put(
    "/api/suppliers/:id",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(`
            UPDATE suppliers
            SET
                name=$1,
                mobile=$2,
                province=$3,
                address=$4,
                ntn_strn=$5
            WHERE id=$6
            RETURNING *
        `, [
            String(
                req.body.name || ""
            ).trim(),

            req.body.mobile || null,
            req.body.province || null,
            req.body.address || null,
            req.body.ntn_strn || null,
            req.params.id
        ]);

        if (!r.rowCount) {
            return fail(
                res,
                404,
                "Supplier not found."
            );
        }

        ok(res, {
            supplier: r.rows[0]
        });
    })
);


app.delete(
    "/api/suppliers/:id",
    auth,
    asyncRoute(async (req, res) => {

        const r = await q(
            `DELETE FROM suppliers
             WHERE id=$1
             RETURNING id`,
            [req.params.id]
        );

        if (!r.rowCount) {
            return fail(
                res,
                404,
                "Supplier not found."
            );
        }

        ok(res, {
            message: "Supplier deleted."
        });
    })
);


/* =========================================================
   PURCHASES
   ========================================================= */

app.get(
    "/api/purchases",
    auth,
    asyncRoute(async (_, res) => {

        const r = await q(`
            SELECT
                p.*,

                COALESCE(
                    p.article_name,
                    a.article_name
                ) AS article_name,

                COALESCE(
                    p.article_code,
                    a.article_code
                ) AS article_code,

                COALESCE(
                    p.size,
                    a.size
                ) AS size,

                COALESCE(
                    p.colour,
                    a.colour
                ) AS colour

            FROM purchases p

            LEFT JOIN articles a
                ON a.id=p.article_id

            ORDER BY p.created_at DESC
        `);

        ok(res, {
            purchases: r.rows
        });
    })
);


app.post(
    "/api/purchases",
    auth,
    asyncRoute(async (req, res) => {

        const client =
            await pool.connect();

        try {

            await client.query("BEGIN");

            const article =
                await client.query(`
                    SELECT *
                    FROM articles
                    WHERE id=$1
                    FOR UPDATE
                `, [
                    req.body.article_id
                ]);

            if (!article.rowCount) {
                throw new Error(
                    "Article not found."
                );
            }

            const qty =
                Number(req.body.quantity);

            const price =
                money(
                    req.body.purchase_price
                );

            if (qty <= 0 || price < 0) {
                throw new Error(
                    "Invalid purchase quantity or price."
                );
            }


            /* ==========================================
               SUPPLIER
               ========================================== */

            let supplierName = null;

            if (String(
                req.body.supplier_name || ""
            ).trim()) {

                supplierName =
                    String(
                        req.body.supplier_name
                    ).trim();

            } else if (req.body.supplier_id) {

                const s =
                    await client.query(
                        `SELECT name
                         FROM suppliers
                         WHERE id=$1`,
                        [req.body.supplier_id]
                    );

                if (!s.rowCount) {
                    throw new Error(
                        "Supplier not found."
                    );
                }

                supplierName =
                    s.rows[0].name;
            }


            /* ==========================================
               PURCHASE WITH ARTICLE SNAPSHOT
               ========================================== */

            const purchase =
                await client.query(`
                    INSERT INTO purchases
                    (
                        article_id,

                        article_name,
                        article_code,
                        size,
                        colour,

                        quantity,
                        purchase_price,

                        supplier_id,
                        supplier_name,

                        created_by
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        $9,
                        $10
                    )
                    RETURNING *
                `, [
                    article.rows[0].id,

                    article.rows[0].article_name,
                    article.rows[0].article_code,
                    article.rows[0].size,
                    article.rows[0].colour,

                    qty,
                    price,

                    req.body.supplier_id || null,
                    supplierName,

                    req.user.id
                ]);


            /* ==========================================
               UPDATE STOCK
               ========================================== */

            await client.query(`
                UPDATE articles
                SET
                    quantity=quantity+$1,
                    purchase_price=$2
                WHERE id=$3
            `, [
                qty,
                price,
                req.body.article_id
            ]);


            await client.query("COMMIT");

            ok(res, {
                purchase:
                    purchase.rows[0]
            });

        } catch (err) {

            await client.query(
                "ROLLBACK"
            );

            fail(
                res,
                400,
                err.message ||
                    "Purchase failed."
            );

        } finally {

            client.release();
        }
    })
);


/* =========================================================
   SALES
   ========================================================= */

function invoiceNo() {

    const d = new Date();

    const date =
        d.getFullYear() +
        String(
            d.getMonth() + 1
        ).padStart(2, "0") +
        String(
            d.getDate()
        ).padStart(2, "0");

    return `UBG-${date}-${Date.now()
        .toString(36)
        .toUpperCase()}`;
}


app.get(
    "/api/sales",
    auth,
    asyncRoute(async (_, res) => {

        const r = await q(`
            SELECT *
            FROM sales
            ORDER BY created_at DESC
        `);

        ok(res, {
            sales: r.rows
        });
    })
);


app.get(
    "/api/sales/:id",
    auth,
    asyncRoute(async (req, res) => {

        const sale = await q(
            `SELECT *
             FROM sales
             WHERE id=$1`,
            [req.params.id]
        );

        if (!sale.rowCount) {
            return fail(
                res,
                404,
                "Invoice not found."
            );
        }

        const items = await q(`
            SELECT *
            FROM sale_items
            WHERE sale_id=$1
            ORDER BY id
        `, [
            req.params.id
        ]);

        ok(res, {
            sale: {
                ...sale.rows[0],
                items: items.rows
            }
        });
    })
);


app.post(
    "/api/sales",
    auth,
    asyncRoute(async (req, res) => {

        const client =
            await pool.connect();

        try {

            await client.query("BEGIN");

            const rawItems =
                Array.isArray(req.body.items)
                    ? req.body.items
                    : [];

            if (!rawItems.length) {
                throw new Error(
                    "Invoice must contain at least one item."
                );
            }


            /* Merge duplicate article lines */

            const map = new Map();

            for (const x of rawItems) {

                const id =
                    Number(x.article_id);

                const qty =
                    Number(x.quantity);

                const rate =
                    Number(x.rate);

                if (
                    !id ||
                    qty <= 0 ||
                    rate <= 0
                ) {
                    throw new Error(
                        "Invalid article quantity or rate."
                    );
                }

                if (map.has(id)) {

                    const old =
                        map.get(id);

                    old.quantity += qty;

                } else {

                    map.set(
                        id,
                        {
                            article_id: id,
                            quantity: qty,
                            rate
                        }
                    );
                }
            }

            const items =
                [...map.values()];

            const ids =
                items.map(
                    x => x.article_id
                );


            const articles =
                await client.query(`
                    SELECT *
                    FROM articles
                    WHERE id=ANY($1::bigint[])
                    FOR UPDATE
                `, [
                    ids
                ]);

            if (
                articles.rowCount !==
                ids.length
            ) {
                throw new Error(
                    "One or more articles are invalid."
                );
            }


            const articleMap =
                new Map(
                    articles.rows.map(
                        a => [
                            String(a.id),
                            a
                        ]
                    )
                );


            let subtotal = 0;

            for (const item of items) {

                const article =
                    articleMap.get(
                        String(
                            item.article_id
                        )
                    );

                if (
                    item.quantity >
                    Number(article.quantity)
                ) {
                    throw new Error(
                        `${article.article_name}: insufficient stock.`
                    );
                }

                item.article =
                    article;

                item.line_total =
                    money(
                        item.quantity *
                        item.rate
                    );

                subtotal +=
                    item.line_total;
            }

            subtotal =
                money(subtotal);


            const taxPercent =
                Math.max(
                    0,
                    Number(
                        req.body.tax_percent || 0
                    )
                );

            const taxAmount =
                money(
                    subtotal *
                    taxPercent /
                    100
                );

            const grandTotal =
                money(
                    subtotal +
                    taxAmount
                );

            const paid =
                money(
                    req.body.paid_amount || 0
                );

            if (
                paid < 0 ||
                paid > grandTotal
            ) {
                throw new Error(
                    "Invalid paid amount."
                );
            }


            const paymentType =
                req.body.payment_type ===
                "Online"
                    ? "Online"
                    : "Cash";


            let payment = null;

            if (paid > 0) {

                if (
                    paymentType ===
                    "Online" &&
                    !req.body.payment
                ) {
                    throw new Error(
                        "Online payment details are required."
                    );
                }

                payment =
                    validatePayment(
                        req.body.payment || {
                            payment_type:
                                "Cash",
                            amount: paid
                        }
                    );

                if (
                    money(
                        payment.amount
                    ) !== paid
                ) {
                    throw new Error(
                        "Payment amount does not match paid amount."
                    );
                }
            }


            let customer = null;

            if (req.body.customer_id) {

                const c =
                    await client.query(
                        `SELECT *
                         FROM customers
                         WHERE id=$1`,
                        [req.body.customer_id]
                    );

                if (!c.rowCount) {
                    throw new Error(
                        "Customer not found."
                    );
                }

                customer =
                    c.rows[0];
            }


            const invoice =
                invoiceNo();


            const sale =
                await client.query(`
                    INSERT INTO sales
                    (
                        invoice_no,
                        customer_id,
                        customer_name,
                        mobile,
                        province,
                        address,
                        payment_type,
                        online_method,
                        subtotal,
                        tax_percent,
                        tax_amount,
                        grand_total,
                        paid_amount,
                        balance,
                        created_by
                    )
                    VALUES
                    (
                        $1,$2,$3,$4,$5,$6,$7,$8,
                        $9,$10,$11,$12,$13,$14,$15
                    )
                    RETURNING *
                `, [
                    invoice,

                    customer?.id ||
                        null,

                    customer?.name ||
                        "Walk-in Customer",

                    customer?.mobile ||
                        null,

                    customer?.province ||
                        null,

                    customer?.address ||
                        null,

                    paymentType,

                    paymentType ===
                    "Online"
                        ? req.body.online_method ||
                          payment?.method
                        : null,

                    subtotal,
                    taxPercent,
                    taxAmount,
                    grandTotal,
                    paid,

                    money(
                        grandTotal -
                        paid
                    ),

                    req.user.id
                ]);


            const saleId =
                sale.rows[0].id;


            for (const item of items) {

                const a =
                    item.article;


                /*
                   Article snapshot sale_items mein
                   already save ho raha hai.
                */

                await client.query(`
                    INSERT INTO sale_items
                    (
                        sale_id,
                        article_id,

                        article_name,
                        article_code,
                        size,
                        colour,

                        quantity,
                        rate,
                        line_total
                    )
                    VALUES
                    (
                        $1,$2,$3,$4,$5,$6,$7,$8,$9
                    )
                `, [
                    saleId,

                    a.id,

                    a.article_name,
                    a.article_code,
                    a.size,
                    a.colour,

                    item.quantity,
                    item.rate,
                    item.line_total
                ]);


                await client.query(`
                    UPDATE articles
                    SET quantity=quantity-$1
                    WHERE id=$2
                `, [
                    item.quantity,
                    a.id
                ]);
            }


            if (
                payment &&
                paid > 0
            ) {

                await client.query(`
                    INSERT INTO payments
                    (
                        sale_id,
                        customer_name,
                        amount,
                        payment_type,
                        method,
                        reference_no,
                        bank_name,
                        cheque_no,
                        status
                    )
                    VALUES
                    (
                        $1,$2,$3,$4,$5,$6,$7,$8,
                        'Completed'
                    )
                `, [
                    saleId,

                    customer?.name ||
                        "Walk-in Customer",

                    payment.amount,

                    payment.payment_type,
                    payment.method,

                    payment.reference_no ||
                        null,

                    payment.bank_name ||
                        null,

                    payment.cheque_no ||
                        null
                ]);
            }


            await client.query(
                "COMMIT"
            );

            ok(res, {
                sale: {
                    ...sale.rows[0],
                    items
                }
            });

        } catch (err) {

            await client.query(
                "ROLLBACK"
            );

            fail(
                res,
                400,
                err.message ||
                    "Sale failed."
            );

        } finally {

            client.release();
        }
    })
);


/* =========================================================
   PAYMENTS
   ========================================================= */

app.get(
    "/api/payments",
    auth,
    asyncRoute(async (req, res) => {

        const where = [];
        const params = [];

        if (req.query.method) {

            params.push(
                req.query.method
            );

            where.push(
                `p.method=$${params.length}`
            );
        }

        if (req.query.from) {

            params.push(
                req.query.from
            );

            where.push(
                `p.created_at >= $${params.length}::date`
            );
        }

        if (req.query.to) {

            params.push(
                req.query.to
            );

            where.push(
                `p.created_at < ($${params.length}::date + INTERVAL '1 day')`
            );
        }


        const r =
            await q(`
                SELECT
                    p.*,
                    s.invoice_no
                FROM payments p
                LEFT JOIN sales s
                    ON s.id=p.sale_id

                ${
                    where.length
                        ? "WHERE " +
                          where.join(
                              " AND "
                          )
                        : ""
                }

                ORDER BY p.created_at DESC
            `, params);


        ok(res, {
            payments: r.rows
        });
    })
);


app.post(
    "/api/payments",
    auth,
    asyncRoute(async (req, res) => {

        const client =
            await pool.connect();

        try {

            await client.query(
                "BEGIN"
            );

            const sale =
                await client.query(`
                    SELECT *
                    FROM sales
                    WHERE id=$1
                    FOR UPDATE
                `, [
                    req.body.sale_id
                ]);

            if (!sale.rowCount) {
                throw new Error(
                    "Invoice not found."
                );
            }

            const s =
                sale.rows[0];

            const amount =
                money(
                    req.body.amount
                );

            if (amount <= 0) {
                throw new Error(
                    "Payment must be greater than zero."
                );
            }

            if (
                amount >
                Number(s.balance)
            ) {
                throw new Error(
                    "Payment cannot exceed outstanding balance."
                );
            }


            const payment =
                validatePayment({
                    ...req.body,
                    amount
                });


            const newPaid =
                money(
                    Number(
                        s.paid_amount
                    ) + amount
                );

            const newBalance =
                money(
                    Number(
                        s.grand_total
                    ) - newPaid
                );


            await client.query(`
                INSERT INTO payments
                (
                    sale_id,
                    customer_name,
                    amount,
                    payment_type,
                    method,
                    reference_no,
                    bank_name,
                    cheque_no,
                    status
                )
                VALUES
                (
                    $1,$2,$3,$4,$5,$6,$7,$8,
                    'Completed'
                )
            `, [
                s.id,
                s.customer_name,
                amount,
                payment.payment_type,
                payment.method,

                payment.reference_no ||
                    null,

                payment.bank_name ||
                    null,

                payment.cheque_no ||
                    null
            ]);


            const updated =
                await client.query(`
                    UPDATE sales
                    SET
                        paid_amount=$1,
                        balance=$2
                    WHERE id=$3
                    RETURNING *
                `, [
                    newPaid,
                    newBalance,
                    s.id
                ]);


            await client.query(
                "COMMIT"
            );

            ok(res, {
                payment,

                sale:
                    updated.rows[0]
            });

        } catch (err) {

            await client.query(
                "ROLLBACK"
            );

            fail(
                res,
                400,
                err.message ||
                    "Payment failed."
            );

        } finally {

            client.release();
        }
    })
);


/* =========================================================
   DASHBOARD
   ========================================================= */

app.get(
    "/api/dashboard",
    auth,
    asyncRoute(async (_, res) => {

        const [
            articles,
            stock,
            todaySales,
            pending,
            todayPayments,
            low,
            sales,
            purchases
        ] = await Promise.all([

            q(`
                SELECT COUNT(*)::int n
                FROM articles
            `),

            q(`
                SELECT
                    COALESCE(
                        SUM(quantity),
                        0
                    )::int n
                FROM articles
            `),

            q(`
                SELECT
                    COALESCE(
                        SUM(grand_total),
                        0
                    ) n
                FROM sales
                WHERE created_at >= CURRENT_DATE
            `),

            q(`
                SELECT
                    COALESCE(
                        SUM(balance),
                        0
                    ) n
                FROM sales
                WHERE balance>0
            `),

            q(`
                SELECT
                    COALESCE(
                        SUM(amount),
                        0
                    ) n
                FROM payments
                WHERE created_at >= CURRENT_DATE
            `),

            q(`
                SELECT COUNT(*)::int n
                FROM articles
                WHERE quantity BETWEEN 1 AND 5
            `),

            q(`
                SELECT *
                FROM sales
                ORDER BY created_at DESC
                LIMIT 5
            `),

            /*
               LEFT JOIN + snapshot fields
               means deleted articles remain visible.
            */

            q(`
                SELECT
                    p.*,

                    COALESCE(
                        p.article_name,
                        a.article_name
                    ) AS article_name,

                    COALESCE(
                        p.article_code,
                        a.article_code
                    ) AS article_code,

                    COALESCE(
                        p.size,
                        a.size
                    ) AS size,

                    COALESCE(
                        p.colour,
                        a.colour
                    ) AS colour

                FROM purchases p

                LEFT JOIN articles a
                    ON a.id=p.article_id

                ORDER BY p.created_at DESC
                LIMIT 5
            `)
        ]);


        ok(res, {

            dashboard: {

                total_articles:
                    articles.rows[0].n,

                total_stock:
                    stock.rows[0].n,

                today_sales:
                    todaySales.rows[0].n,

                pending_balance:
                    pending.rows[0].n,

                today_payments:
                    todayPayments.rows[0].n,

                low_stock:
                    low.rows[0].n,

                recent_sales:
                    sales.rows,

                recent_purchases:
                    purchases.rows
            }
        });
    })
);


/* =========================================================
   REPORTS
   ========================================================= */

app.get(
    "/api/reports",
    auth,
    asyncRoute(async (req, res) => {

        const type =
            req.query.type ||
            "sales";

        const from =
            req.query.from;

        const to =
            req.query.to;


        let rows = [];

        let summary = {
            records: 0,
            total: 0,
            paid: 0,
            balance: 0
        };


        /* ==========================================
           SALES REPORT
           ========================================== */

        if (type === "sales") {

            const where = [];
            const params = [];

            if (from) {

                params.push(from);

                where.push(
                    `created_at >= $${params.length}::date`
                );
            }

            if (to) {

                params.push(to);

                where.push(
                    `created_at < ($${params.length}::date + INTERVAL '1 day')`
                );
            }


            const r =
                await q(`
                    SELECT *
                    FROM sales

                    ${
                        where.length
                            ? "WHERE " +
                              where.join(
                                  " AND "
                              )
                            : ""
                    }

                    ORDER BY created_at DESC
                `, params);


            rows = r.rows;

            summary.records =
                rows.length;

            summary.total =
                rows.reduce(
                    (s, x) =>
                        s +
                        Number(
                            x.grand_total
                        ),
                    0
                );

            summary.paid =
                rows.reduce(
                    (s, x) =>
                        s +
                        Number(
                            x.paid_amount
                        ),
                    0
                );

            summary.balance =
                rows.reduce(
                    (s, x) =>
                        s +
                        Number(
                            x.balance
                        ),
                    0
                );
        }


        /* ==========================================
           STOCK REPORT
           ========================================== */

        else if (type === "stock") {

            const r =
                await q(`
                    SELECT *,
                        quantity *
                        purchase_price
                            AS stock_value
                    FROM articles
                    ORDER BY article_name
                `);

            rows = r.rows;

            summary.records =
                rows.length;

            summary.total =
                rows.reduce(
                    (s, x) =>
                        s +
                        Number(
                            x.stock_value
                        ),
                    0
                );
        }


        /* ==========================================
           PAYMENT REPORT
           ========================================== */

        else if (type === "payments") {

            const r =
                await q(`
                    SELECT
                        p.*,
                        s.invoice_no
                    FROM payments p
                    LEFT JOIN sales s
                        ON s.id=p.sale_id
                    ORDER BY p.created_at DESC
                `);

            rows = r.rows;

            summary.records =
                rows.length;

            summary.total =
                rows.reduce(
                    (s, x) =>
                        s +
                        Number(
                            x.amount
                        ),
                    0
                );
        }


        /* ==========================================
           ALERT REPORT
           ========================================== */

        else if (type === "alerts") {

            const r =
                await q(`
                    SELECT *
                    FROM articles
                    WHERE quantity<=5
                    ORDER BY
                        quantity,
                        article_name
                `);

            rows = r.rows;

            summary.records =
                rows.length;
        }


        else {

            return fail(
                res,
                400,
                "Invalid report type."
            );
        }


        ok(res, {
            rows,
            summary
        });
    })
);


/* =========================================================
   FRONTEND
   ========================================================= */

app.get(
    "/",
    (_, res) =>
        res.sendFile(
            path.join(
                __dirname,
                "index.html"
            )
        )
);


app.get(
    "/style.css",
    (_, res) =>
        res.sendFile(
            path.join(
                __dirname,
                "style.css"
            )
        )
);


app.get(
    "/script.js",
    (_, res) =>
        res.sendFile(
            path.join(
                __dirname,
                "script.js"
            )
        )
);


/* =========================================================
   ERRORS
   ========================================================= */

app.use(
    "/api",
    (_, res) =>
        fail(
            res,
            404,
            "API endpoint not found."
        )
);


app.use(
    (err, _, res, __) => {

        console.error(err);

        if (err.code === "23505") {
            return fail(
                res,
                409,
                "This record already exists."
            );
        }

        if (err.code === "23503") {
            return fail(
                res,
                400,
                "This record is linked to existing data."
            );
        }

        fail(
            res,
            500,
            "Internal server error."
        );
    }
);


/* =========================================================
   START
   ========================================================= */

async function start() {

    if (!process.env.JWT_SECRET) {

        console.error(
            "JWT_SECRET is missing in .env"
        );

        process.exit(1);
    }

    try {

        await initDB();

        app.listen(
            PORT,
            () => {

                console.log(`
========================================
 U&BG ERP ONLINE
 Server: http://localhost:${PORT}
========================================
                `);
            }
        );

    } catch (err) {

        console.error(
            "Database startup failed:",
            err.message
        );

        process.exit(1);
    }
}

start();