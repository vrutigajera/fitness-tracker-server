require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const app = express();
app.use(cors());
app.use(express.json());

// ================== DB CONNECTION ==================
const DB_URL = process.env.MONGODB_URL;
mongoose
    .connect(DB_URL)
    .then(() => console.log("✅ Successfully connected to MongoDB"))
    .catch((err) => console.error("❌ Database connection error:", err));

// ================== SCHEMAS & MODELS ==================
const baseUserSchema = new mongoose.Schema({
    id: String,
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    phone: { type: String, required: true }, // Added phone
    gender: String,
    address: String,
    registrationDate: String,
    password: { type: String, required: true },
    role: { type: String, required: true },
});

const Admin = mongoose.model("Admin", baseUserSchema, "admins");
const Member = mongoose.model("Member", baseUserSchema, "members");
const Trainer = mongoose.model("Trainer", baseUserSchema, "trainers");

// Schedule Schema
const scheduleSchema = new mongoose.Schema({
    title: String,
    description: String,
    date: String,
    time: String,
    trainer: { type: mongoose.Schema.Types.ObjectId, ref: "Trainer" },
    bookedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "Member" }],
});
const Schedule = mongoose.model("Schedule", scheduleSchema, "schedules");

// Booking Schema
const bookingSchema = new mongoose.Schema({
    trainerId: { type: mongoose.Schema.Types.ObjectId, ref: "Trainer" },
    memberId: { type: mongoose.Schema.Types.ObjectId, ref: "Member" },
    scheduleId: { type: mongoose.Schema.Types.ObjectId, ref: "Schedule" },
    scheduleDetails: {
        title: String,
        date: String,
        time: String
    },
    status: { type: String, default: "pending" },
    createdAt: { type: Date, default: Date.now },
});

// Membership Schema
const membershipSchema = new mongoose.Schema({
    memberId: { type: mongoose.Schema.Types.ObjectId, ref: "Member", required: true },
    membershipType: { type: String, required: true }, // Basic, Premium, VIP
    amount: { type: Number, required: true },
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date, required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const Booking = mongoose.model("Booking", bookingSchema, "bookings");
const Membership = mongoose.model("Membership", membershipSchema, "memberships");

function getModelByRole(role) {
    if (role === "admin") return Admin;
    if (role === "member") return Member;
    if (role === "trainer") return Trainer;
    throw new Error("Invalid role");
}

// ================== AUTH ROUTES ==================
app.post("/register", async(req, res) => {
    try {
        const { name, email, phone, password, role } = req.body;
        if (!name || !email || !phone || !password || !role) {
            return res.status(400).json({ message: "All fields are required" });
        }

        let Model;
        if (role === "member") Model = Member;
        else if (role === "trainer") Model = Trainer;
        else if (role === "admin") Model = Admin;
        else return res.status(400).json({ message: "Invalid role" });

        const existing = await Model.findOne({ email });
        if (existing) return res.status(400).json({ message: "User already exists" });

        const newUser = new Model(req.body);
        await newUser.save();

        res.status(201).json({ message: `✅ ${role} registered successfully` });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

app.post("/login", async(req, res) => {
    try {
        const { email, password, role } = req.body;
        if (!email || !password || !role)
            return res.status(400).json({ message: "All fields are required" });

        const Model = getModelByRole(role);
        const user = await Model.findOne({ email, password });
        if (!user)
            return res
                .status(401)
                .json({ message: "Invalid credentials for this role" });

        const token = jwt.sign({ userId: user._id, role: user.role },
            process.env.JWT_SECRET, { expiresIn: "1h" }
        );

        res.json({ token, role: user.role, name: user.name, id: user._id });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ================== MIDDLEWARE ==================
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res
                .status(403)
                .json({ message: "Access denied: Insufficient role" });
        }
        next();
    };
}

// ================== USER ROUTES ==================
app.get(
    "/all-users",
    authenticateToken,
    authorizeRoles("admin"),
    async(req, res) => {
        try {
            const admins = await Admin.find();
            const members = await Member.find();
            const trainers = await Trainer.find();
            res.json({ admins, members, trainers });
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error fetching users", error: err.message });
        }
    }
);

// ================== SCHEDULE ROUTES ==================
// Trainer: create schedule
app.post(
    "/schedules",
    authenticateToken,
    authorizeRoles("trainer"),
    async(req, res) => {
        try {
            const { title, description, date, time } = req.body;
            const newSchedule = new Schedule({
                title,
                description,
                date,
                time,
                trainer: req.user.userId,
            });
            await newSchedule.save();
            res
                .status(201)
                .json({ message: "✅ Schedule created", schedule: newSchedule });
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error creating schedule", error: err.message });
        }
    }
);

// All users can view schedules
app.get(
    "/schedules",
    authenticateToken,
    authorizeRoles("trainer", "member", "admin"),
    async(req, res) => {
        try {
            const schedules = await Schedule.find()
                .populate("trainer", "name email")
                .populate("bookedBy", "name email");
            res.json(schedules);
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error fetching schedules", error: err.message });
        }
    }
);

// Member: book schedule
app.post(
    "/schedules/:id/book",
    authenticateToken,
    authorizeRoles("member"),
    async(req, res) => {
        try {
            const schedule = await Schedule.findById(req.params.id);
            if (!schedule) return res.status(404).json({ message: "Schedule not found" });

            if (!schedule.bookedBy.includes(req.user.userId)) {
                schedule.bookedBy.push(req.user.userId);
                await schedule.save();
            }
            res.json({ message: "✅ Schedule booked", schedule });
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error booking schedule", error: err.message });
        }
    }
);

// Get current member info with membership details
app.get("/members/me", authenticateToken, authorizeRoles("member"), async(req, res) => {
    try {
        const member = await Member.findById(req.user.userId);
        if (!member) return res.status(404).json({ message: "Member not found" });

        // Get active membership
        const activeMembership = await Membership.findOne({
            memberId: req.user.userId,
            isActive: true,
            endDate: { $gte: new Date() }
        });

        res.json({
            name: member.name || "",
            phone: member.phone || "",
            email: member.email || "",
            membership: activeMembership ? {
                type: activeMembership.membershipType,
                amount: activeMembership.amount,
                startDate: activeMembership.startDate,
                endDate: activeMembership.endDate,
                isActive: activeMembership.isActive
            } : null
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Update member profile
app.put("/members/me", authenticateToken, authorizeRoles("member"), async(req, res) => {
    try {
        const { name, phone } = req.body;
        const member = await Member.findByIdAndUpdate(
            req.user.userId, { name, phone }, { new: true }
        );
        if (!member) return res.status(404).json({ message: "Member not found" });

        res.json({ message: "Profile updated successfully", member });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Get trainer profile
app.get("/trainers/me", authenticateToken, authorizeRoles("trainer"), async(req, res) => {
    try {
        const trainer = await Trainer.findById(req.user.userId);
        if (!trainer) return res.status(404).json({ message: "Trainer not found" });

        res.json({
            name: trainer.name || "",
            phone: trainer.phone || "",
            email: trainer.email || ""
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Update trainer profile
app.put("/trainers/me", authenticateToken, authorizeRoles("trainer"), async(req, res) => {
    try {
        const { name, phone } = req.body;
        const trainer = await Trainer.findByIdAndUpdate(
            req.user.userId, { name, phone }, { new: true }
        );
        if (!trainer) return res.status(404).json({ message: "Trainer not found" });

        res.json({ message: "Profile updated successfully", trainer });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Get admin profile
app.get("/admins/me", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const admin = await Admin.findById(req.user.userId);
        if (!admin) return res.status(404).json({ message: "Admin not found" });

        res.json({
            name: admin.name || "",
            phone: admin.phone || "",
            email: admin.email || ""
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// Update admin profile
app.put("/admins/me", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const { name, phone } = req.body;
        const admin = await Admin.findByIdAndUpdate(
            req.user.userId, { name, phone }, { new: true }
        );
        if (!admin) return res.status(404).json({ message: "Admin not found" });

        res.json({ message: "Profile updated successfully", admin });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ================== TRAINER & ADMIN FILTERED SCHEDULES ==================
// Get all trainers
app.get("/trainers", authenticateToken, authorizeRoles("admin", "member", "trainer"), async(req, res) => {
    try {
        const trainers = await Trainer.find({}, "name email phone");
        const formattedTrainers = trainers.map(trainer => ({
            _id: trainer._id,
            name: trainer.name,
            email: trainer.email,
            phone: trainer.phone,
            displayName: `${trainer.email} (${trainer.name})`
        }));
        res.json(formattedTrainers);
    } catch (err) {
        res.status(500).json({ message: "Error fetching trainers", error: err.message });
    }
});

// Trainer: get their own schedules
app.get(
    "/schedules/my-schedules",
    authenticateToken,
    authorizeRoles("trainer"),
    async(req, res) => {
        try {
            const schedules = await Schedule.find({ trainer: req.user.userId })
                .populate("trainer", "name email")
                .populate("bookedBy", "name email")
                .sort({ date: 1, time: 1 });
            res.json(schedules);
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error fetching trainer schedules", error: err.message });
        }
    }
);
// Admin & Member: get schedules of a trainer by EMAIL
app.get(
    "/schedules/by-trainer-email/:trainerEmail",
    authenticateToken,
    authorizeRoles("admin", "member"),
    async(req, res) => {
        try {
            const trainerEmail = decodeURIComponent(req.params.trainerEmail);

            const trainer = await Trainer.findOne({ email: trainerEmail });
            if (!trainer) {
                return res.status(404).json({ message: "Trainer not found" });
            }

            const schedules = await Schedule.find({ trainer: trainer._id })
                .populate("trainer", "name email")
                .populate("bookedBy", "name email")
                .sort({ date: 1, time: 1 });

            res.json(schedules);
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error fetching trainer schedules", error: err.message });
        }
    }
);

// ================== BOOKING ROUTES ==================
// Member: create booking request using trainer EMAIL
app.post("/bookings/book", authenticateToken, authorizeRoles("member"), async(req, res) => {
    try {
        const { trainerEmail, memberName, memberPhone, schedule } = req.body;
        if (!trainerEmail) {
            return res.status(400).json({ message: "Trainer email is required" });
        }

        // Check if member has active membership
        const activeMembership = await Membership.findOne({
            memberId: req.user.userId,
            isActive: true,
            endDate: { $gte: new Date() }
        });

        if (!activeMembership) {
            return res.status(403).json({ message: "Active membership required to book sessions" });
        }

        // find trainer by email
        const trainer = await Trainer.findOne({ email: trainerEmail });
        if (!trainer) {
            return res.status(404).json({ message: "Trainer not found" });
        }

        let scheduleId = null;

        // Parse schedule string to extract details
        let scheduleDetails = { title: null, date: null, time: null };
        if (typeof schedule === 'string' && schedule.includes('on') && schedule.includes('at')) {
            const parts = schedule.split(' on ');
            if (parts.length === 2) {
                const [title, dateTimePart] = parts;
                const dateTimeMatch = dateTimePart.match(/(.+) at (.+)/);
                if (dateTimeMatch) {
                    const [, date, time] = dateTimeMatch;
                    scheduleDetails = {
                        title: title.trim(),
                        date: date.trim(),
                        time: time.trim()
                    };
                }
            }
        }

        const newBooking = new Booking({
            trainerId: trainer._id,
            memberId: req.user.userId,
            scheduleId: scheduleId,
            scheduleDetails: scheduleDetails
        });
        await newBooking.save();

        res.status(201).json({ message: "✅ Booking requested successfully", booking: newBooking });
    } catch (err) {
        res.status(500).json({ message: "Error creating booking", error: err.message });
    }
});


// Member: get my bookings
app.get(
    "/bookings/my-bookings",
    authenticateToken,
    authorizeRoles("member"),
    async(req, res) => {
        try {
            const bookings = await Booking.find({ memberId: req.user.userId })
                .populate("trainerId", "name email phone")
                .populate("scheduleId", "title date time")
                .sort({ createdAt: -1 });
            res.json(bookings);
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error fetching bookings", error: err.message });
        }
    }
);

// Trainer: get all bookings for this trainer
app.get(
    "/bookings/trainer-bookings",
    authenticateToken,
    authorizeRoles("trainer"),
    async(req, res) => {
        try {
            const bookings = await Booking.find({ trainerId: req.user.userId })
                .populate("memberId", "name email phone")
                .populate("scheduleId", "title date time")
                .sort({ createdAt: -1 });
            res.json(bookings);
        } catch (err) {
            res.status(500).json({ message: "Error fetching trainer bookings", error: err.message });
        }
    }
);

// ================== ADMIN: Trainer Bookings Summary ==================
app.get(
    "/admin/trainer-bookings-summary",
    authenticateToken,
    authorizeRoles("admin"),
    async(req, res) => {
        try {
            // Fetch all trainers
            const trainers = await Trainer.find({}, "name email phone");

            const summary = [];

            for (const trainer of trainers) {
                // Fetch bookings for this trainer
                const bookings = await Booking.find({ trainerId: trainer._id })
                    .populate("memberId", "name email phone")
                    .populate("scheduleId", "title date time")
                    .sort({ createdAt: -1 });

                // Map bookings to proper format
                const formattedBookings = bookings.map((b) => ({
                    status: b.status,
                    member: b.memberId ? { name: b.memberId.name, email: b.memberId.email } : null,
                    schedule: b.scheduleDetails || (b.scheduleId ? {
                        title: b.scheduleId.title,
                        date: b.scheduleId.date,
                        time: b.scheduleId.time,
                    } : { title: null, date: null, time: null }),
                    bookedAt: b.createdAt,
                }));

                summary.push({
                    trainer,
                    bookings: formattedBookings,
                });
            }

            res.json({ summary });
        } catch (err) {
            console.error("Error fetching trainer bookings summary:", err);
            res.status(500).json({ message: "Server error", error: err.message });
        }
    }
);

// ================== DELETE USER ROUTES ==================
app.delete(
    "/delete-user/:role/:id",
    authenticateToken,
    authorizeRoles("admin"),
    async(req, res) => {
        try {
            const { role, id } = req.params;

            let Model;
            if (role === "member") Model = Member;
            else if (role === "trainer") Model = Trainer;
            else return res.status(400).json({ message: "Invalid role" });

            const user = await Model.findById(id);
            if (!user) return res.status(404).json({ message: `${role} not found` });

            await Model.findByIdAndDelete(id);

            // Optional: Delete related bookings
            if (role === "member") {
                await Booking.deleteMany({ memberId: id });
            } else if (role === "trainer") {
                await Booking.deleteMany({ trainerId: id });
                await Schedule.deleteMany({ trainer: id });
            }

            res.json({ message: `✅ ${role} deleted successfully` });
        } catch (err) {
            console.error("Error deleting user:", err);
            res.status(500).json({ message: "Server error", error: err.message });
        }
    }
);


// Trainer: update booking status
app.put(
    "/bookings/:id/status",
    authenticateToken,
    authorizeRoles("trainer"),
    async(req, res) => {
        try {
            const { status } = req.body;
            if (!["pending", "approved", "rejected"].includes(status)) {
                return res.status(400).json({ message: "Invalid status" });
            }

            const booking = await Booking.findById(req.params.id);
            if (!booking) return res.status(404).json({ message: "Booking not found" });

            if (booking.trainerId.toString() !== req.user.userId) {
                return res.status(403).json({ message: "Access denied" });
            }

            booking.status = status;
            await booking.save();
            res.json({ message: "✅ Booking status updated", booking });
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error updating booking status", error: err.message });
        }
    }
);

// Member: get schedules of a trainer by EMAIL
app.get("/schedules/trainer-email/:trainerEmail",
    authenticateToken,
    authorizeRoles("member"),
    async(req, res) => {
        try {
            const trainerEmail = req.params.trainerEmail;

            // Find trainer by email
            const trainer = await Trainer.findOne({ email: trainerEmail });
            if (!trainer) {
                return res.status(404).json({ message: "Trainer not found" });
            }

            // Find schedules for that trainer
            const schedules = await Schedule.find({ trainer: trainer._id })
                .populate("trainer", "name email")
                .populate("bookedBy", "name email")
                .sort({ date: 1, time: 1 });

            res.json(schedules);
        } catch (err) {
            res.status(500).json({ message: "Error fetching trainer schedules", error: err.message });
        }
    }
);


// ================== GET ALL BOOKED SCHEDULES ==================
app.get(
    "/schedules/booked/all",
    authenticateToken,
    authorizeRoles("admin", "trainer"),
    async(req, res) => {
        try {
            const bookedSchedules = await Schedule.find({
                    bookedBy: { $exists: true, $not: { $size: 0 } },
                })
                .populate("trainer", "name email")
                .populate("bookedBy", "name email")
                .sort({ date: 1, time: 1 });

            res.json(bookedSchedules);
        } catch (err) {
            res
                .status(500)
                .json({ message: "Error fetching booked schedules", error: err.message });
        }
    }
);

// ================== SALARY MANAGEMENT ROUTES ==================
// Get trainer salary
app.get("/admin/trainer-salary/:trainerId", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        let salaryData = await TrainerSalary.findOne({ trainerId: req.params.trainerId });

        if (!salaryData) {
            // Create default salary record if doesn't exist
            salaryData = new TrainerSalary({
                trainerId: req.params.trainerId,
                currentSalary: 0,
                bonuses: 0,
                deductions: 0
            });
            await salaryData.save();
        }

        res.json({
            currentSalary: salaryData.currentSalary.toString(),
            bonuses: salaryData.bonuses.toString(),
            deductions: salaryData.deductions.toString()
        });
    } catch (err) {
        res.status(500).json({ message: "Error fetching salary", error: err.message });
    }
});

// Update trainer salary
app.put("/admin/trainer-salary/:trainerId", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const { currentSalary, bonuses, deductions } = req.body;

        let salaryData = await TrainerSalary.findOne({ trainerId: req.params.trainerId });

        if (!salaryData) {
            salaryData = new TrainerSalary({
                trainerId: req.params.trainerId,
                currentSalary: parseInt(currentSalary),
                bonuses: parseInt(bonuses || 0),
                deductions: parseInt(deductions || 0)
            });
        } else {
            salaryData.currentSalary = parseInt(currentSalary);
            salaryData.bonuses = parseInt(bonuses || 0);
            salaryData.deductions = parseInt(deductions || 0);
            salaryData.updatedAt = new Date();
        }

        // Update total earnings based on completed sessions and monthly salary
        const completedSessions = await Booking.countDocuments({
            trainerId: req.params.trainerId,
            status: "approved"
        });
        // Total earnings = (monthly salary * months worked) + (session bonus * completed sessions)
        const monthsWorked = Math.max(1, Math.floor(completedSessions / 10)); // Assume 10 sessions per month
        salaryData.totalEarnings = (salaryData.currentSalary * monthsWorked) + (completedSessions * 500); // 500 per session bonus

        await salaryData.save();
        res.json({ message: "Salary updated successfully" });
    } catch (err) {
        res.status(500).json({ message: "Error updating salary", error: err.message });
    }
});

// Get dashboard stats
app.get("/admin/dashboard-stats", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const totalTrainers = await Trainer.countDocuments();
        const totalMembers = await Member.countDocuments();
        const totalBookings = await Booking.countDocuments();
        const completedBookings = await Booking.countDocuments({ status: "approved" });

        // Calculate total trainer salaries from database
        const salaryRecords = await TrainerSalary.find({});
        const totalTrainerSalaries = salaryRecords.reduce((total, record) => {
            return total + (record.currentSalary + record.bonuses - record.deductions);
        }, 0);

        // If no salary records, use default calculation
        const finalTrainerSalaries = totalTrainerSalaries > 0 ? totalTrainerSalaries : totalTrainers * 45000;

        // Calculate total membership revenue from actual memberships
        const membershipRevenue = await Membership.aggregate([
            { $match: { isActive: true } },
            { $group: { _id: null, total: { $sum: "$amount" } } }
        ]);
        const totalMembershipRevenue = membershipRevenue.length > 0 ? membershipRevenue[0].total : 0;

        res.json({
            totalTrainers,
            totalMembers,
            totalTrainerSalaries: finalTrainerSalaries,
            totalMembershipRevenue: totalMembershipRevenue,
            activeBookings: totalBookings - completedBookings,
            completedSessions: completedBookings
        });
    } catch (err) {
        res.status(500).json({ message: "Error fetching stats", error: err.message });
    }
});

// Trainer Salary Schema
const trainerSalarySchema = new mongoose.Schema({
    trainerId: { type: mongoose.Schema.Types.ObjectId, ref: "Trainer", required: true },
    currentSalary: { type: Number, default: 45000 },
    bonuses: { type: Number, default: 5000 },
    deductions: { type: Number, default: 0 },
    totalEarnings: { type: Number, default: 0 },
    updatedAt: { type: Date, default: Date.now }
});
const TrainerSalary = mongoose.model("TrainerSalary", trainerSalarySchema, "trainersalaries");

// Update trainer salary endpoint for trainer dashboard
app.get("/trainer/salary", authenticateToken, authorizeRoles("trainer"), async(req, res) => {
    try {
        // Get trainer's salary data
        let salaryData = await TrainerSalary.findOne({ trainerId: req.user.userId });

        if (!salaryData) {
            // Create default salary record for new trainer with 0 salary
            salaryData = new TrainerSalary({
                trainerId: req.user.userId,
                currentSalary: 0,
                bonuses: 0,
                deductions: 0,
                totalEarnings: 0
            });
            await salaryData.save();
        }

        // Get trainer's booking stats
        const completedBookings = await Booking.countDocuments({
            trainerId: req.user.userId,
            status: "approved"
        });
        const pendingBookings = await Booking.countDocuments({
            trainerId: req.user.userId,
            status: "pending"
        });
        const rejectedBookings = await Booking.countDocuments({
            trainerId: req.user.userId,
            status: "rejected"
        });

        const monthlyEarnings = salaryData.currentSalary + salaryData.bonuses - salaryData.deductions;

        res.json({
            currentSalary: salaryData.currentSalary,
            totalEarnings: salaryData.totalEarnings,
            monthlyEarnings: monthlyEarnings,
            completedSessions: completedBookings,
            pendingSessions: pendingBookings,
            rejectedSessions: rejectedBookings,
            bonuses: salaryData.bonuses,
            deductions: salaryData.deductions
        });
    } catch (err) {
        res.status(500).json({ message: "Error fetching salary data", error: err.message });
    }
});

// Membership Plans Schema
const membershipPlanSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: String, required: true },
    amount: { type: Number, required: true },
    duration: { type: Number, default: 1 },
    features: [String],
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const MembershipPlan = mongoose.model("MembershipPlan", membershipPlanSchema, "membershipplans");

// ================== MEMBERSHIP ROUTES ==================
// Buy membership
app.post("/memberships/buy", authenticateToken, authorizeRoles("member"), async(req, res) => {
    try {
        const { membershipType, amount, duration } = req.body; // duration in months

        // Deactivate any existing active membership
        await Membership.updateMany({ memberId: req.user.userId, isActive: true }, { isActive: false });

        // Create new membership
        const endDate = new Date();
        endDate.setMonth(endDate.getMonth() + parseInt(duration));

        const newMembership = new Membership({
            memberId: req.user.userId,
            membershipType,
            amount: parseInt(amount),
            endDate,
            isActive: true
        });

        await newMembership.save();

        res.status(201).json({
            message: "Membership purchased successfully",
            membership: newMembership
        });
    } catch (err) {
        res.status(500).json({ message: "Error purchasing membership", error: err.message });
    }
});

// Get member's membership history
app.get("/memberships/my-memberships", authenticateToken, authorizeRoles("member"), async(req, res) => {
    try {
        const memberships = await Membership.find({ memberId: req.user.userId })
            .sort({ createdAt: -1 });
        res.json(memberships);
    } catch (err) {
        res.status(500).json({ message: "Error fetching memberships", error: err.message });
    }
});

// ================== ADMIN MEMBERSHIP ROUTES ==================
// Get member memberships
app.get("/admin/member-memberships/:memberId", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const memberships = await Membership.find({ memberId: req.params.memberId })
            .sort({ createdAt: -1 });
        res.json(memberships);
    } catch (err) {
        res.status(500).json({ message: "Error fetching member memberships", error: err.message });
    }
});

// Get all membership plans
app.get("/admin/membership-plans", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const plans = await MembershipPlan.find({ isActive: true }).sort({ amount: 1 });
        res.json(plans);
    } catch (err) {
        res.status(500).json({ message: "Error fetching plans", error: err.message });
    }
});

// Add new membership plan
app.post("/admin/membership-plans", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const newPlan = new MembershipPlan(req.body);
        await newPlan.save();
        res.status(201).json({ message: "Plan created successfully", plan: newPlan });
    } catch (err) {
        res.status(500).json({ message: "Error creating plan", error: err.message });
    }
});

// Update membership plan
app.put("/admin/membership-plans/:planId", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        const updatedPlan = await MembershipPlan.findByIdAndUpdate(
            req.params.planId, 
            req.body, 
            { new: true }
        );
        res.json({ message: "Plan updated successfully", plan: updatedPlan });
    } catch (err) {
        res.status(500).json({ message: "Error updating plan", error: err.message });
    }
});

// Delete membership plan
app.delete("/admin/membership-plans/:planId", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        await MembershipPlan.findByIdAndUpdate(req.params.planId, { isActive: false });
        res.json({ message: "Plan deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: "Error deleting plan", error: err.message });
    }
});

// Get dynamic membership plans for frontend
app.get("/membership-plans", async(req, res) => {
    try {
        const plans = await MembershipPlan.find({ isActive: true }).sort({ amount: 1 });
        res.json(plans);
    } catch (err) {
        res.status(500).json({ message: "Error fetching plans", error: err.message });
    }
});

// ================== REPORTS ENDPOINT ==================
app.get("/admin/reports", authenticateToken, authorizeRoles("admin"), async(req, res) => {
    try {
        // Get all trainers with salary data
        const trainers = await Trainer.find({});
        const trainerReports = [];
        let totalTrainerCost = 0;
        
        for (const trainer of trainers) {
            const salaryData = await TrainerSalary.findOne({ trainerId: trainer._id });
            const completedSessions = await Booking.countDocuments({ 
                trainerId: trainer._id, 
                status: "approved" 
            });
            
            const salary = salaryData ? 
                (salaryData.currentSalary + salaryData.bonuses - salaryData.deductions) : 45000;
            
            trainerReports.push({
                name: trainer.name,
                email: trainer.email,
                salary: salary,
                sessions: completedSessions,
                joinDate: trainer.createdAt || new Date()
            });
            
            totalTrainerCost += salary;
        }
        
        // Get all members with membership data
        const members = await Member.find({});
        const memberReports = [];
        let totalMemberRevenue = 0;
        
        for (const member of members) {
            const activeMembership = await Membership.findOne({ 
                memberId: member._id, 
                isActive: true 
            });
            
            const allMemberships = await Membership.find({ memberId: member._id });
            const totalPaid = allMemberships.reduce((sum, m) => sum + m.amount, 0);
            
            let status = "inactive";
            if (activeMembership) {
                status = new Date(activeMembership.endDate) >= new Date() ? "active" : "expired";
            }
            
            memberReports.push({
                name: member.name,
                email: member.email,
                membershipType: activeMembership?.membershipType || null,
                membershipAmount: totalPaid,
                membershipEndDate: activeMembership?.endDate || null,
                status: status
            });
            
            totalMemberRevenue += totalPaid;
        }
        
        res.json({
            trainers: trainerReports,
            members: memberReports,
            totalTrainerCost,
            totalMemberRevenue
        });
    } catch (err) {
        res.status(500).json({ message: "Error generating reports", error: err.message });
    }
});

// ================== START SERVER ==================
const PORT = 5000;
app.listen(PORT, () =>
    console.log(`🚀 Server running on http://localhost:${PORT}`)
);