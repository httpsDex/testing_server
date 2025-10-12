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
        SELECT u.*, r.role_name, s.*, CONCAT(s.first_name, ' ', s.last_name) as full_name, s.department
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


// ====================== SUMMARY & RANKING ENDPOINTS ======================

// Get summary reports
app.get("/api/teaching-summary", authenticate, requireRole(["Teaching Evaluator"]), (req, res) => {
    let query = "";
    let params = [];

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
        connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Summary query error:", err);
            return res.status(500).json({ message: "Server error" });
        }
        res.json(results);
    });
});



app.get("/api/non-teaching-summary", authenticate, requireRole(["Non-Teaching Evaluator"]),(req, res) => {
    let query = "";
    let params = [];

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

    connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Summary query error:", err);
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







// Add these endpoints to your existing server.js file

// ====================== EMPLOYEE DASHBOARD ENDPOINTS ======================

// Get employee dashboard statistics
app.get("/api/employee/dashboard", authenticate, requireRole(["Teaching Employee", "Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;
    const roleId = req.user.role_id;

    let query = "";
    let params = [staffId];

    if (roleId === 3) { // Teaching Employee
        query = `
            SELECT 
                te.final_total_points as current_score,
                (SELECT COUNT(*) FROM certificates WHERE staff_id = ? AND status IN ('accepted', 'pending', 'rejected')) as certificate_count
            FROM teaching_evaluations te
            WHERE te.staff_id = ? AND te.period_id = 1
            LIMIT 1
        `;
        params = [staffId, staffId];
    } else if (roleId === 4) { // Non-Teaching Employee
        query = `
            SELECT 
                nte.final_total_points as current_score,
                (SELECT COUNT(*) FROM certificates WHERE staff_id = ? AND status IN ('accepted', 'pending', 'rejected')) as certificate_count,
                (SELECT COUNT(*) FROM peer_evaluation_assignments WHERE evaluator_staff_id = ? AND assignment_status = 'pending') as pending_evaluations,
                (SELECT COUNT(*) FROM peer_evaluation_assignments WHERE evaluator_staff_id = ? AND assignment_status = 'completed') as completed_evaluations
            FROM nonteaching_evaluations nte
            WHERE nte.staff_id = ? AND nte.period_id = 1
            LIMIT 1
        `;
        params = [staffId, staffId, staffId, staffId];
    }

    connection.query(query, params, (err, results) => {
        if (err) {
            console.error("Employee dashboard query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        const stats = results[0] || {
            current_score: 0,
            certificate_count: 0,
            pending_evaluations: 0,
            completed_evaluations: 0
        };

        res.json({
            currentScore: stats.current_score ? stats.current_score.toFixed(2) + '%' : 'N/A',
            certificateCount: stats.certificate_count || 0,
            pendingEvaluations: stats.pending_evaluations || 0,
            completedEvaluations: stats.completed_evaluations || 0
        });
    });
});

// ====================== PEER EVALUATION ENDPOINTS (For Non-Teaching Employees) ======================

// Get assigned peer evaluations for employee to complete
app.get("/api/employee/peer-evaluations", authenticate, requireRole(["Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            pea.assignment_id,
            pea.evaluatee_staff_id,
            CONCAT(s.first_name, ' ', s.last_name) as employee_name,
            s.department,
            pea.assignment_status as status,
            pea.assigned_date,
            pe.peer_eval_id,
            pe.evaluation_status
        FROM peer_evaluation_assignments pea
        JOIN staff s ON pea.evaluatee_staff_id = s.staff_id
        LEFT JOIN peer_evaluations pe ON pea.assignment_id = pe.assignment_id
        WHERE pea.evaluator_staff_id = ? AND pea.period_id = 1
        ORDER BY pea.assignment_status ASC, pea.assigned_date DESC
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Employee peer evaluations query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        const evaluations = results.map(row => ({
            assignment_id: row.assignment_id,
            employee_name: row.employee_name,
            department: row.department,
            status: row.evaluation_status || 'pending'
        }));

        res.json(evaluations);
    });
});

// Submit peer evaluation
app.post("/api/employee/peer-evaluation", authenticate, requireRole(["Non-Teaching Employee"]), (req, res) => {
    const { employee, communication, teamwork, problemSolving, comments } = req.body;
    const staffId = req.user.staff_id;

    // First, get the assignment_id
    const getAssignmentQuery = `
        SELECT pea.assignment_id
        FROM peer_evaluation_assignments pea
        JOIN staff s ON pea.evaluatee_staff_id = s.staff_id
        WHERE pea.evaluator_staff_id = ? 
        AND CONCAT(s.first_name, ' ', s.last_name) = ?
        AND pea.period_id = 1
        LIMIT 1
    `;

    connection.query(getAssignmentQuery, [staffId, employee], (err, results) => {
        if (err) {
            console.error("Get assignment error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "Assignment not found" });
        }

        const assignmentId = results[0].assignment_id;

        // Insert peer evaluation
        const insertQuery = `
            INSERT INTO peer_evaluations 
            (assignment_id, evaluation_status, submitted_date, comments, 
             job_attitude, work_habits, personal_relation)
            VALUES (?, 'submitted', NOW(), ?, ?, ?, ?)
        `;

        connection.query(insertQuery, [
            assignmentId,
            comments,
            communication,
            teamwork,
            problemSolving
        ], (err, result) => {
            if (err) {
                console.error("Insert peer evaluation error:", err);
                return res.status(500).json({ message: "Server error" });
            }

            // Update assignment status
            const updateAssignmentQuery = `
                UPDATE peer_evaluation_assignments 
                SET assignment_status = 'completed', completed_date = NOW()
                WHERE assignment_id = ?
            `;

            connection.query(updateAssignmentQuery, [assignmentId], (err) => {
                if (err) {
                    console.error("Update assignment error:", err);
                }
            });

            res.json({ message: "Evaluation submitted successfully" });
        });
    });
});

// ====================== TEACHING EVALUATION SUMMARY ENDPOINTS ======================

// Get teaching evaluation summary for employee
app.get("/api/employee/teaching-summary", authenticate, requireRole(["Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            ep.period_name as period,
            CONCAT(evaluator.first_name, ' ', evaluator.last_name) as evaluator,
            tes1.score as teaching_competence,
            tes2.score as effectiveness,
            tes3.score as professional_growth,
            te.final_total_points as total_score,
            te.evaluation_status as status,
            te.evaluation_id,
            te.evaluation_date
        FROM teaching_evaluations te
        JOIN evaluation_periods ep ON te.period_id = ep.period_id
        JOIN users u ON te.evaluator_user_id = u.user_id
        JOIN staff evaluator ON u.staff_id = evaluator.staff_id
        LEFT JOIN teaching_evaluation_scores tes1 ON te.evaluation_id = tes1.evaluation_id AND tes1.type_id = 1
        LEFT JOIN teaching_evaluation_scores tes2 ON te.evaluation_id = tes2.evaluation_id AND tes2.type_id = 2
        LEFT JOIN teaching_evaluation_scores tes3 ON te.evaluation_id = tes3.evaluation_id AND tes3.type_id = 4
        WHERE te.staff_id = ?
        ORDER BY te.evaluation_date DESC
        LIMIT 10
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Teaching summary query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        res.json(results);
    });
});

// Get detailed teaching evaluation report
app.get("/api/employee/teaching-report/:id", authenticate, requireRole(["Teaching Employee"]), (req, res) => {
    const evaluationId = req.params.id;
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            te.*,
            s.first_name,
            s.last_name,
            s.department,
            s.position,
            ep.period_name,
            ep.academic_year,
            CONCAT(evaluator.first_name, ' ', evaluator.last_name) as evaluator_name,
            tes1.score as student_evaluation,
            tes2.score as peer_evaluation,
            tes3.score as dean_evaluation,
            tes4.score as professional_growth,
            tes5.score as school_services
        FROM teaching_evaluations te
        JOIN staff s ON te.staff_id = s.staff_id
        JOIN evaluation_periods ep ON te.period_id = ep.period_id
        JOIN users u ON te.evaluator_user_id = u.user_id
        JOIN staff evaluator ON u.staff_id = evaluator.staff_id
        LEFT JOIN teaching_evaluation_scores tes1 ON te.evaluation_id = tes1.evaluation_id AND tes1.type_id = 1
        LEFT JOIN teaching_evaluation_scores tes2 ON te.evaluation_id = tes2.evaluation_id AND tes2.type_id = 2
        LEFT JOIN teaching_evaluation_scores tes3 ON te.evaluation_id = tes3.evaluation_id AND tes3.type_id = 3
        LEFT JOIN teaching_evaluation_scores tes4 ON te.evaluation_id = tes4.evaluation_id AND tes4.type_id = 4
        LEFT JOIN teaching_evaluation_scores tes5 ON te.evaluation_id = tes5.evaluation_id AND tes5.type_id = 5
        WHERE te.evaluation_id = ? AND te.staff_id = ?
        LIMIT 1
    `;

    connection.query(query, [evaluationId, staffId], (err, results) => {
        if (err) {
            console.error("Teaching report query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "Evaluation not found" });
        }

        res.json(results[0]);
    });
});

// ====================== NON-TEACHING EVALUATION SUMMARY ENDPOINTS ======================

// Get non-teaching evaluation summary for employee
app.get("/api/employee/non-teaching-summary", authenticate, requireRole(["Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            ep.period_name as period,
            CONCAT(evaluator.first_name, ' ', evaluator.last_name) as evaluator,
            nte.peer_evaluation_total as productivity,
            nte.additional_evaluations as attitude,
            nte.certificate_points as promotional_competence,
            nte.final_total_points * 0.25 as attendance,
            nte.final_total_points as total_score,
            nte.evaluation_status as status,
            nte.evaluation_id,
            nte.evaluation_date
        FROM nonteaching_evaluations nte
        JOIN evaluation_periods ep ON nte.period_id = ep.period_id
        JOIN users u ON nte.evaluator_user_id = u.user_id
        JOIN staff evaluator ON u.staff_id = evaluator.staff_id
        WHERE nte.staff_id = ?
        ORDER BY nte.evaluation_date DESC
        LIMIT 10
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Non-teaching summary query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        res.json(results);
    });
});

// Get detailed non-teaching evaluation report
app.get("/api/employee/non-teaching-report/:id", authenticate, requireRole(["Non-Teaching Employee"]), (req, res) => {
    const evaluationId = req.params.id;
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            nte.*,
            s.first_name,
            s.last_name,
            s.department,
            s.position,
            ep.period_name,
            ep.academic_year,
            CONCAT(evaluator.first_name, ' ', evaluator.last_name) as evaluator_name
        FROM nonteaching_evaluations nte
        JOIN staff s ON nte.staff_id = s.staff_id
        JOIN evaluation_periods ep ON nte.period_id = ep.period_id
        JOIN users u ON nte.evaluator_user_id = u.user_id
        JOIN staff evaluator ON u.staff_id = evaluator.staff_id
        WHERE nte.evaluation_id = ? AND nte.staff_id = ?
        LIMIT 1
    `;

    connection.query(query, [evaluationId, staffId], (err, results) => {
        if (err) {
            console.error("Non-teaching report query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "Evaluation not found" });
        }

        res.json(results[0]);
    });
});

// ====================== CERTIFICATE ENDPOINTS (For Employees) ======================

// Get employee's own certificates
app.get("/api/employee/certificates", authenticate, requireRole(["Teaching Employee", "Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            certificate_id,
            certificate_name as title,
            certificate_type as type,
            organizer,
            duration_start as date,
            status,
            submitted_date,
            evaluator_comments
        FROM certificates
        WHERE staff_id = ?
        ORDER BY submitted_date DESC
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Employee certificates query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        res.json(results);
    });
});

// Submit new certificate
app.post("/api/employee/certificates", authenticate, requireRole(["Teaching Employee", "Non-Teaching Employee"]), (req, res) => {
    const { name, type, startDate, endDate, organizers } = req.body;
    const staffId = req.user.staff_id;

    // Calculate points based on certificate type
    let points = 3.0; // Default points
    if (type === 'Workshop') points = 4.0;
    else if (type === 'Training') points = 3.5;
    else if (type === 'Conference') points = 5.0;
    else if (type === 'Award') points = 4.5;

    const query = `
        INSERT INTO certificates 
        (staff_id, certificate_name, certificate_type, organizer, 
         duration_start, duration_end, points_value, date_received, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `;

    connection.query(query, [
        staffId,
        name,
        type,
        organizers,
        startDate,
        endDate,
        points,
        startDate
    ], (err, result) => {
        if (err) {
            console.error("Submit certificate error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        res.json({ 
            message: "Certificate submitted successfully",
            certificate_id: result.insertId
        });
    });
});

// ====================== RANKING ENDPOINTS (For Employees) ======================

// Get teaching employee ranking history
app.get("/api/employee/teaching-ranking", authenticate, requireRole(["Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            ep.academic_year as year,
            CASE WHEN ep.semester = '1st' THEN te.final_total_points ELSE NULL END as first_semester,
            CASE WHEN ep.semester = '2nd' THEN te.final_total_points ELSE NULL END as second_semester,
            AVG(te.final_total_points) as annual_average
        FROM teaching_evaluations te
        JOIN evaluation_periods ep ON te.period_id = ep.period_id
        WHERE te.staff_id = ?
        GROUP BY ep.academic_year
        ORDER BY ep.academic_year DESC
        LIMIT 3
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Teaching ranking query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        res.json(results);
    });
});

// Get non-teaching employee ranking history
app.get("/api/employee/non-teaching-ranking", authenticate, requireRole(["Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            ep.academic_year as year,
            CASE WHEN ep.semester = '1st' THEN nte.final_total_points ELSE NULL END as first_semester,
            CASE WHEN ep.semester = '2nd' THEN nte.final_total_points ELSE NULL END as second_semester,
            AVG(nte.final_total_points) as annual_average
        FROM nonteaching_evaluations nte
        JOIN evaluation_periods ep ON nte.period_id = ep.period_id
        WHERE nte.staff_id = ?
        GROUP BY ep.academic_year
        ORDER BY ep.academic_year DESC
        LIMIT 3
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Non-teaching ranking query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        res.json(results);
    });
});

// Get promotion eligibility
app.get("/api/employee/promotion-eligibility", authenticate, requireRole(["Teaching Employee", "Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            evaluation_cycle,
            cycle_start_year,
            cycle_end_year,
            total_evaluations,
            average_points,
            minimum_required_points,
            is_eligible,
            promotion_status
        FROM promotion_eligibility
        WHERE staff_id = ?
        ORDER BY cycle_start_year DESC
        LIMIT 1
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Promotion eligibility query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        if (results.length === 0) {
            return res.json({
                is_eligible: 0,
                average_points: 0,
                message: "No promotion data available yet"
            });
        }

        res.json(results[0]);
    });
});

// ====================== PROFILE ENDPOINTS ======================

// Get employee profile
app.get("/api/employee/profile", authenticate, requireRole(["Teaching Employee", "Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;

    const query = `
        SELECT 
            s.*,
            u.username,
            u.email,
            sc.category_name
        FROM staff s
        JOIN users u ON s.staff_id = u.staff_id
        JOIN staff_categories sc ON s.category_id = sc.category_id
        WHERE s.staff_id = ?
    `;

    connection.query(query, [staffId], (err, results) => {
        if (err) {
            console.error("Profile query error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "Profile not found" });
        }

        res.json(results[0]);
    });
});

// Update employee profile
app.put("/api/employee/profile", authenticate, requireRole(["Teaching Employee", "Non-Teaching Employee"]), (req, res) => {
    const staffId = req.user.staff_id;
    const { firstName, lastName, phone, email } = req.body;

    connection.beginTransaction(err => {
        if (err) {
            console.error("Transaction error:", err);
            return res.status(500).json({ message: "Server error" });
        }

        // Update staff table
        const updateStaffQuery = `
            UPDATE staff 
            SET first_name = ?, last_name = ?, phone = ?, updated_at = NOW()
            WHERE staff_id = ?
        `;

        connection.query(updateStaffQuery, [firstName, lastName, phone, staffId], (err) => {
            if (err) {
                return connection.rollback(() => {
                    console.error("Update staff error:", err);
                    res.status(500).json({ message: "Server error" });
                });
            }

            // Update users table
            const updateUserQuery = `
                UPDATE users 
                SET email = ?
                WHERE staff_id = ?
            `;

            connection.query(updateUserQuery, [email, staffId], (err) => {
                if (err) {
                    return connection.rollback(() => {
                        console.error("Update user error:", err);
                        res.status(500).json({ message: "Server error" });
                    });
                }

                connection.commit(err => {
                    if (err) {
                        return connection.rollback(() => {
                            console.error("Commit error:", err);
                            res.status(500).json({ message: "Server error" });
                        });
                    }

                    res.json({ message: "Profile updated successfully" });
                });
            });
        });
    });
});








// ====================== START SERVER ======================
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
