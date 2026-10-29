CREATE DATABASE IF NOT EXISTS campusfix;
USE campusfix;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'student',
    roll_number VARCHAR(100) NULL,
    course_year VARCHAR(100) NULL,
    profile_photo LONGTEXT NULL,
    phone VARCHAR(20) NULL,
    Residence VARCHAR(100) NULL,
    room_no VARCHAR(50) NULL,
    emp_id VARCHAR(40) NULL,
    dept VARCHAR(80) NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_users_email (email),
    UNIQUE KEY uq_users_roll (roll_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS staff (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL,
    dept VARCHAR(80) NULL,
    role VARCHAR(60) NULL,
    phone VARCHAR(20) NULL,
    password VARCHAR(255) NOT NULL,
    active TINYINT NOT NULL DEFAULT 1,
    profile_photo LONGTEXT NULL,
    must_change_password TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_staff_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS complaints (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    location VARCHAR(255) NULL,
    category VARCHAR(100) NULL,
    priority VARCHAR(50) NOT NULL DEFAULT 'Medium',
    status VARCHAR(50) NOT NULL DEFAULT 'Pending',
    photo LONGTEXT NULL,
    client_cid VARCHAR(64) NULL,
    assigned_to INT NULL,
    escalated TINYINT NOT NULL DEFAULT 0,
    rating TINYINT NULL,
    resolved_at DATETIME NULL,
    resolved_by VARCHAR(100) NULL,
    notified_at DATETIME NULL,
    resolution_note TEXT NULL,
    resolution_photo LONGTEXT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_student_cid (student_id, client_cid),
    KEY idx_complaints_status (status),
    KEY idx_complaints_assigned (assigned_to),
    KEY idx_complaints_created (created_at),
    CONSTRAINT fk_complaints_student FOREIGN KEY (student_id)
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_complaints_staff FOREIGN KEY (assigned_to)
        REFERENCES staff(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS complaint_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    complaint_id INT NOT NULL,
    kind VARCHAR(20) NULL,
    msg VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_log_complaint (complaint_id),
    CONSTRAINT fk_log_complaint FOREIGN KEY (complaint_id)
        REFERENCES complaints(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
