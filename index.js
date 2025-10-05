const express = require("express");
const app = express();
const moment = require("moment");
const mysql = require("mysql");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 1804;
const JWT_SECRET = "supersecretkey";

app.use(express.static(path.join(__dirname, "public")));

const logger = (req, res, next) => {
    console.log(`${req.protocol}://${req.get('host')}${req.originalUrl} : ${moment().format()}`)
    next()
}

app.use(logger);
app.use(cors());
app.use(express.json());

// Connection to mysql
const connection = mysql.createConnection({
    host: "bhbygkjrpoqisbhd0eap-mysql.services.clever-cloud.com",
    user: "ufpfe1xcyfgkcwub",
    password: "zIppx86ygVzh0TcrRX7x",
    database: "bhbygkjrpoqisbhd0eap"
});

connection.connect((err) => {
    if (err) {
        console.error("❌ MySQL connection failed:", err);
        return;
    }
    console.log("✅ MySQL connected!");
});

// ====================== AUTH HELPERS ======================
const authenticate = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(403).json({ message: "No token provided" });

    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Invalid token" });

        req.user = decoded;
        next();
    });
};

// ✅ Role-based middleware
const requireRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role_name)) {
        return res.status(403).json({ message: "Forbidden: insufficient role" });
    }
    next();
};



// ====================== LOGIN ENDPOINT ======================
app.post("/api/auth/login", (req, res) => {
    const { usernameOrEmail, password } = req.body;

    if (!usernameOrEmail || !password) {
        return res.status(400).json({ message: "Missing credentials" });
    }

    const query = `
        SELECT u.*, r.role_name, s.*, 
               CONCAT(s.first_name, ' ', s.last_name) as full_name,
               s.department
        FROM users u
        JOIN user_roles r ON u.role_id = r.role_id
        LEFT JOIN staff s ON u.staff_id = s.staff_id
        WHERE u.username = ? OR u.email = ?
        LIMIT 1
    `;


    connection.query(query, [usernameOrEmail, usernameOrEmail], async (err, results) => {
        if (err) {
            console.error("Login query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const user = results[0];

        // ✅ Verify password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // ✅ Generate JWT
        const token = jwt.sign(
            {
                user_id: user.user_id,
                username: user.username,
                role_id: user.role_id,
                role_name: user.role_name,
                staff_id: user.staff_id,
                department: user.department,
                name: `${user.first_name} ${user.last_name}`,
                position: user.position
            },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        // ✅ Update last login
        connection.query("UPDATE users SET last_login = NOW() WHERE user_id = ?", [user.user_id]);

        res.json({
            message: "Login successful",
            accessToken: token,
            user: {
                id: user.user_id,
                username: user.username,
                email: user.email,
                role_id: user.role_id,
                role_name: user.role_name,
                staff_id: user.staff_id,
                name: `${user.first_name} ${user.last_name}`,
                department: user.department,
                position: user.position
            },
        });
    });
});

// ====================== DASHBOARD ENDPOINTS ======================

// Get dashboard statistics
app.get("/api/dashboard", authenticate, (req, res) => {
    const userId = req.user.user_id;
    const userRole = req.user.role_name;
    const categoryId = req.user.category_id;

    let query = "";
    let params = [];

    if (userRole === "Teaching Evaluator") {
        query = `
            SELECT 
                COUNT(DISTINCT s.staff_id) as handled_employees,
                SUM(CASE WHEN te.evaluation_status = 'draft' THEN 1 ELSE 0 END) as pending_evaluations,
                SUM(CASE WHEN te.evaluation_status = 'completed' THEN 1 ELSE 0 END) as completed_evaluations,
                (SELECT COUNT(*) FROM certificates WHERE status = 'pending' AND staff_id IN 
                    (SELECT staff_id FROM staff WHERE category_id = 1 AND department_head_id = ?)) as pending_certificates
            FROM staff s
            LEFT JOIN teaching_evaluations te ON s.staff_id = te.staff_id AND te.period_id = 1
            WHERE s.category_id = 1 AND s.department_head_id = ?
        `;
        params = [req.user.staff_id, req.user.staff_id];
    } else if (userRole === "Non-Teaching Evaluator") {
        query = `
            SELECT 
                COUNT(DISTINCT s.staff_id) as handled_employees,
                SUM(CASE WHEN nte.evaluation_status = 'draft' THEN 1 ELSE 0 END) as pending_evaluations,
                SUM(CASE WHEN nte.evaluation_status = 'completed' THEN 1 ELSE 0 END) as completed_evaluations,
                (SELECT COUNT(*) FROM certificates WHERE status = 'pending' AND staff_id IN 
                    (SELECT staff_id FROM staff WHERE category_id = 2 AND department_head_id = ?)) as pending_certificates
            FROM staff s
            LEFT JOIN nonteaching_evaluations nte ON s.staff_id = nte.staff_id AND nte.period_id = 1
            WHERE s.category_id = 2 AND s.department_head_id = ?
        `;
        params = [req.user.staff_id, req.user.staff_id];
    }

    connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Dashboard query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        const stats = results[0] || {
            handled_employees: 0,
            pending_evaluations: 0,
            completed_evaluations: 0,
            pending_certificates: 0
        };

        res.json({
            handledEmployees: stats.handled_employees,
            pendingEvaluations: stats.pending_evaluations,
            completedEvaluations: stats.completed_evaluations,
            pendingCertificates: stats.pending_certificates
        });
    });
});

// ====================== EVALUATION ENDPOINTS ======================

// Get teaching evaluations
app.get("/api/evaluations", authenticate, requireRole(["Teaching Evaluator"]), (req, res) => {
    const query = `
        SELECT 
            s.staff_id,
            CONCAT(s.first_name, ' ', s.last_name) as employee_name,
            s.department,
            s.position,
            te.evaluation_status as status,
            te.final_total_points as total_score,
            te.evaluation_id
        FROM staff s
        LEFT JOIN teaching_evaluations te ON s.staff_id = te.staff_id AND te.period_id = 1
        WHERE s.category_id = 1 AND s.department_head_id = ?
        ORDER BY s.first_name, s.last_name
    `;

    connection.query(query, [req.user.staff_id], (err, results) => {
        if (err) {
            console.error("Teaching evaluations query error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        res.json(results);
    });
});

// Get non-teaching evaluations
app.get("/api/non-teaching-evaluations", authenticate, requireRole(["Non-Teaching Evaluator"]), (req, res) => {
    const query = `
        SELECT 
            s.staff_id,
            CONCAT(s.first_name, ' ', s.last_name) as employee_name,
            s.department,
            s.position,
            nte.evaluation_status as status,
            nte.final_total_points as total_score,
            nte.evaluation_id
        FROM staff s
        LEFT JOIN nonteaching_evaluations nte ON s.staff_id = nte.staff_id AND nte.period_id = 1
        WHERE s.category_id = 2 AND s.department_head_id = ?
        ORDER BY s.first_name, s.last_name DESC
    `;

    connection.query(query, [req.user.staff_id], (err, results) => {
        if (err) {
            console.error("Non-teaching evaluations query error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        res.json(results);
    });
});

// ====================== PEER EVALUATION ENDPOINTS ======================

// Get peer evaluation assignments
app.get("/api/peer-evaluations", authenticate, requireRole(["Non-Teaching Evaluator"]), (req, res) => {
    const query = `
        SELECT 
            pea.assignment_id,
            pea.evaluatee_staff_id,
            CONCAT(s.first_name, ' ', s.last_name) as employee_name,
            s.department,
            dh.staff_id as department_head_id,
            CONCAT(dh.first_name, ' ', dh.last_name) as department_head,
            sdp.staff_id as same_department_peer_id,
            CONCAT(sdp.first_name, ' ', sdp.last_name) as same_department_peer,
            odp.staff_id as external_department_peer_id,
            CONCAT(odp.first_name, ' ', odp.last_name) as external_department_peer,
            pea.assignment_status as status,
            pea.assigned_date
        FROM peer_evaluation_assignments pea
        JOIN staff s ON pea.evaluatee_staff_id = s.staff_id
        LEFT JOIN staff dh ON pea.evaluator_staff_id = dh.staff_id AND pea.evaluator_type = 'department_head'
        LEFT JOIN staff sdp ON pea.evaluator_staff_id = sdp.staff_id AND pea.evaluator_type = 'same_department_peer'
        LEFT JOIN staff odp ON pea.evaluator_staff_id = odp.staff_id AND pea.evaluator_type = 'outsider'
        WHERE pea.period_id = 1
        ORDER BY s.first_name, s.last_name DESC
    `;

    connection.query(query, (err, results) => {
        if (err) {
            console.error("Peer evaluations query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        // Transform the data to group by employee
        const assignmentsByEmployee = {};
        results.forEach(row => {
            if (!assignmentsByEmployee[row.evaluatee_staff_id]) {
                assignmentsByEmployee[row.evaluatee_staff_id] = {
                    id: row.assignment_id,
                    employeeId: row.evaluatee_staff_id,
                    employeeName: row.employee_name,
                    department: row.department,
                    departmentHead: null,
                    sameDepartmentPeer: null,
                    externalDepartmentPeer: null,
                    status: row.status
                };
            }

            if (row.department_head) {
                assignmentsByEmployee[row.evaluatee_staff_id].departmentHead = row.department_head;
            }
            if (row.same_department_peer) {
                assignmentsByEmployee[row.evaluatee_staff_id].sameDepartmentPeer = row.same_department_peer;
            }
            if (row.external_department_peer) {
                assignmentsByEmployee[row.evaluatee_staff_id].externalDepartmentPeer = row.external_department_peer;
            }
        });

        res.json(Object.values(assignmentsByEmployee));
    });
});

// Get employees for peer evaluation modal
app.get("/api/employees", authenticate, requireRole(["Non-Teaching Evaluator"]), (req, res) => {
    const query = `
        SELECT 
            staff_id,
            CONCAT(first_name, ' ', last_name) as name,
            department,
            position,
            category_id
        FROM staff 
        WHERE status = 'active'
        ORDER BY category_id, department, last_name, first_name
    `;

    connection.query(query, (err, results) => {
        if (err) {
            console.error("Employees query error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        res.json(results);
    });
});

// Create peer evaluation assignment
app.post("/api/peer-evaluations", authenticate, requireRole(["Non-Teaching Evaluator"]), (req, res) => {
    const { employeeId, departmentHeadId, sameDepartmentPeerId, externalDepartmentPeerId, evaluationPeriod } = req.body;
    const periodId = 1; // Using the active period

    // Start transaction
    connection.beginTransaction(err => {
        if (err) {
            console.error("Transaction error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        const assignments = [
            { staffId: employeeId, evaluatorId: departmentHeadId, type: 'department_head' },
            { staffId: employeeId, evaluatorId: sameDepartmentPeerId, type: 'same_department_peer' },
            { staffId: employeeId, evaluatorId: externalDepartmentPeerId, type: 'outsider' }
        ];

        let completed = 0;
        let errors = [];

        assignments.forEach(assignment => {
            if (assignment.evaluatorId) {
                const query = `
                    INSERT INTO peer_evaluation_assignments 
                    (evaluatee_staff_id, evaluator_staff_id, period_id, evaluator_type, assigned_by_user_id)
                    VALUES (?, ?, ?, ?, ?)
                `;
                
                connection.query(query, [
                    assignment.staffId,
                    assignment.evaluatorId,
                    periodId,
                    assignment.type,
                    req.user.user_id
                ], (err, result) => {
                    if (err) {
                        errors.push(err);
                    }
                    completed++;

                    if (completed === assignments.length) {
                        if (errors.length > 0) {
                            connection.rollback(() => {
                                res.status(500).json({ message: "Failed to create assignments" });
                            });
                        } else {
                            connection.commit(err => {
                                if (err) {
                                    connection.rollback(() => {
                                        res.status(500).json({ message: "Failed to commit transaction" });
                                    });
                                } else {
                                    res.json({ message: "Peer evaluation assignments created successfully" });
                                }
                            });
                        }
                    }
                });
            } else {
                completed++;
            }
        });
    });
});

// Update peer evaluation assignment
app.put("/api/peer-evaluations/:id", authenticate, requireRole(["Non-Teaching Evaluator"]), (req, res) => {
    // Implementation for updating assignments
    res.json({ message: "Update endpoint - implement based on your needs" });
});

// Delete peer evaluation assignment
app.delete("/api/peer-evaluations/:id", authenticate, requireRole(["Non-Teaching Evaluator"]), (req, res) => {
    const assignmentId = req.params.id;
    
    const query = "DELETE FROM peer_evaluation_assignments WHERE assignment_id = ?";
    
    connection.query(query, [assignmentId], (err, result) => {
        if (err) {
            console.error("Delete assignment error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Assignment not found" });
        }
        
        res.json({ message: "Assignment deleted successfully" });
    });
});

// ====================== CERTIFICATE ENDPOINTS ======================

// Get certificates for approval
app.get("/api/certificates", authenticate, (req, res) => {
    let query = "";
    let params = [];

    if (req.user.role_name === "Teaching Evaluator") {
        query = `
            SELECT 
                c.certificate_id,
                c.staff_id,
                CONCAT(s.first_name, ' ', s.last_name) as employee_name,
                s.department as department,
                c.certificate_name,
                c.certificate_type,
                c.organizer,
                c.duration_start,
                c.duration_end,
                c.points_value,
                c.date_received,
                c.status,
                c.submitted_date
            FROM certificates c
            JOIN staff s ON c.staff_id = s.staff_id
            WHERE s.category_id = 1 AND s.department_head_id = ?
            ORDER BY c.submitted_date DESC
        `;
        params = [req.user.staff_id];
    } else if (req.user.role_name === "Non-Teaching Evaluator") {
        query = `
            SELECT 
                c.certificate_id,
                c.staff_id,
                CONCAT(s.first_name, ' ', s.last_name) as employee_name,
                s.department as department,
                c.certificate_name,
                c.certificate_type,
                c.organizer,
                c.duration_start,
                c.duration_end,
                c.points_value,
                c.date_received,
                c.status,
                c.submitted_date
            FROM certificates c
            JOIN staff s ON c.staff_id = s.staff_id
            WHERE s.category_id = 2
            ORDER BY c.submitted_date DESC
        `;
    }

    connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Certificates query error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        res.json(results);
    });
});

// Update certificate status
app.put("/api/certificates/:id/status", authenticate, (req, res) => {
    const certificateId = req.params.id;
    const { status, comments } = req.body;

    const query = `
        UPDATE certificates 
        SET status = ?, evaluator_id = ?, evaluated_date = NOW(), evaluator_comments = ?
        WHERE certificate_id = ?
    `;

    connection.query(query, [status, req.user.user_id, comments, certificateId], (err, result) => {
        if (err) {
            console.error("Update certificate error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Certificate not found" });
        }

        res.json({ message: "Certificate status updated successfully" });
    });
});

// ====================== SUMMARY & RANKING ENDPOINTS ======================

// Get summary reports
app.get("/api/summary", authenticate, (req, res) => {
    let query = "";
    let params = [];

    if (req.user.role_name === "Teaching Evaluator") {
        query = `
            SELECT 
                s.staff_id,
                CONCAT(s.first_name, ' ', s.last_name) as employee_name,
                s.department as department,
                te.final_total_points as total_score,
                te.evaluation_status as status
            FROM staff s
            LEFT JOIN teaching_evaluations te ON s.staff_id = te.staff_id AND te.period_id = 1
            WHERE s.category_id = 1 AND s.department_head_id = ?
            ORDER BY s.first_name, s.last_name DESC
        `;
        params = [req.user.staff_id];
    } else if (req.user.role_name === "Non-Teaching Evaluator") {
        query = `
            SELECT 
                s.staff_id,
                CONCAT(s.first_name, ' ', s.last_name) as employee_name,
                s.department as department,
                nte.final_total_points as total_score,
                nte.evaluation_status as status
            FROM staff s
            LEFT JOIN nonteaching_evaluations nte ON s.staff_id = nte.staff_id AND nte.period_id = 1
            WHERE s.category_id = 2 AND s.department_head_id = ?
            ORDER BY s.first_name, s.last_name DESC
        `;
        params = [req.user.staff_id];
    }

    connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Summary query error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        res.json(results);
    });
});

// Get employee rankings
app.get("/api/rankings", authenticate, (req, res) => {
    let query = "";
    let params = [];

    if (req.user.role_name === "Teaching Evaluator") {
        query = `
            SELECT 
                s.staff_id,
                CONCAT(s.first_name, ' ', s.last_name) as employee_name,
                s.department as department,
                te.final_total_points as total_score,
                pe.is_eligible as promotion_eligibility,
                pe.promotion_status
            FROM staff s
            LEFT JOIN teaching_evaluations te ON s.staff_id = te.staff_id AND te.period_id = 1
            LEFT JOIN promotion_eligibility pe ON s.staff_id = pe.staff_id AND pe.evaluation_cycle = '2023-2025'
            WHERE s.category_id = 1 AND s.department_head_id = ?
            ORDER BY s.first_name, s.last_name DESC
        `;
        params = [req.user.staff_id];
    } else if (req.user.role_name === "Non-Teaching Evaluator") {
        query = `
            SELECT 
                s.staff_id,
                CONCAT(s.first_name, ' ', s.last_name) as employee_name,
                s.department as department,
                nte.final_total_points as total_score,
                pe.is_eligible as promotion_eligibility,
                pe.promotion_status
            FROM staff s
            LEFT JOIN nonteaching_evaluations nte ON s.staff_id = nte.staff_id AND nte.period_id = 1
            LEFT JOIN promotion_eligibility pe ON s.staff_id = pe.staff_id AND pe.evaluation_cycle = '2023-2025'
            WHERE s.category_id = 2 AND s.department_head_id = ?
            ORDER BY s.first_name, s.last_name DESC
        `;
        params = [req.user.staff_id];
    }

    connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Rankings query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        // Transform data for frontend
        const rankings = results.map((row, index) => ({
            employee_name: row.employee_name,
            department: row.department,
            total_score: row.total_score || 0,
            promotion_eligibility: row.promotion_eligibility ? 1 : 0,
            promotion_status: row.promotion_status
        }));

        res.json(rankings);
    });
});

// ====================== EMPLOYEE MANAGEMENT ENDPOINTS ======================

// Get employees for management
app.get("/api/employees-management", authenticate, (req, res) => {
    let query = "";
    let params = [];

    if (req.user.role_name === "Teaching Evaluator") {
        query = `
            SELECT 
                staff_id,
                employee_id,
                CONCAT(first_name, ' ', last_name) as name,
                department,
                position,
                employment_type,
                status
            FROM staff 
            WHERE category_id = 1 AND department_head_id = ?
            ORDER BY first_name, last_name
        `;
        params = [req.user.staff_id];
    } else if (req.user.role_name === "Non-Teaching Evaluator") {
        query = `
            SELECT 
                staff_id,
                employee_id,
                CONCAT(first_name, ' ', last_name) as name,
                department,
                position,
                employment_type,
                status
            FROM staff 
            WHERE category_id = 2 and department_head_id = ?
            ORDER BY first_name, last_name
        `;
        params = [req.user.staff_id];
    }

    connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Employees management query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        const employees = results.map(row => ({
            id: row.staff_id,
            employeeId: row.employee_id,
            name: row.name,
            department: row.department,
            position: row.position,
            employmentType: row.employment_type === 'full_time' ? 'Full-Time' : 'Part-Time',
            status: row.status === 'active' ? 'Active' : 'Inactive'
        }));

        res.json(employees);
    });
});

// ====================== EVALUATION PERIODS ======================

// Get evaluation periods
app.get("/api/evaluation-periods", authenticate, (req, res) => {
    const query = "SELECT * FROM evaluation_periods ORDER BY start_date DESC";
    
    connection.query(query, (err, results) => {
        if (err) {
            console.error("Evaluation periods query error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        res.json(results);
    });
});

// ====================== START SERVER ======================
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});