-- Cortis 사내 포털 데이터베이스 구조
-- MySQL 8.0 / MariaDB 11.x 공통 사용

CREATE DATABASE IF NOT EXISTS company_portal
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE company_portal;

-- 1. 부서 정보
CREATE TABLE department (
    department_id BIGINT AUTO_INCREMENT,
    department_name VARCHAR(100) NOT NULL,
    extension_number VARCHAR(10),

    PRIMARY KEY (department_id),
    UNIQUE KEY uk_department_name (department_name),
    UNIQUE KEY uk_department_extension (extension_number)
) ENGINE=InnoDB;

-- 2. 임직원 및 로그인 계정
-- 실습 시나리오를 위해 password 컬럼에 평문 비밀번호를 저장합니다.
CREATE TABLE employees (
    employee_id BIGINT AUTO_INCREMENT,
    employee_number VARCHAR(30) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    name VARCHAR(50) NOT NULL,
    email VARCHAR(150) NOT NULL,
    phone VARCHAR(30),
    department_id BIGINT,
    manager_id BIGINT,
    `position` VARCHAR(50),
    `role` ENUM('USER', 'MANAGER', 'ADMIN') NOT NULL DEFAULT 'USER',
    joined_date DATE,

    PRIMARY KEY (employee_id),
    UNIQUE KEY uk_employee_number (employee_number),
    UNIQUE KEY uk_employee_email (email),

    CONSTRAINT fk_employee_department
        FOREIGN KEY (department_id)
        REFERENCES department(department_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL,

    CONSTRAINT fk_employee_manager
        FOREIGN KEY (manager_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB;

-- 3. 공지사항
CREATE TABLE notices (
    notice_id BIGINT AUTO_INCREMENT,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    author_id BIGINT NOT NULL,

    PRIMARY KEY (notice_id),

    CONSTRAINT fk_notice_author
        FOREIGN KEY (author_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 4. 업무 관리
CREATE TABLE tasks (
    task_id BIGINT AUTO_INCREMENT,
    title VARCHAR(200) NOT NULL,
    creator_id BIGINT NOT NULL,
    assignee_id BIGINT,
    department_id BIGINT,
    `status` ENUM('TODO', 'IN_PROGRESS', 'DONE', 'HOLD')
        NOT NULL DEFAULT 'TODO',
    priority ENUM('LOW', 'NORMAL', 'HIGH', 'URGENT')
        NOT NULL DEFAULT 'NORMAL',
    start_date DATE,
    due_date DATE,

    PRIMARY KEY (task_id),

    CONSTRAINT fk_task_creator
        FOREIGN KEY (creator_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT fk_task_assignee
        FOREIGN KEY (assignee_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL,

    CONSTRAINT fk_task_department
        FOREIGN KEY (department_id)
        REFERENCES department(department_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB;

-- 5. 전자결재 문서
CREATE TABLE approval_documents (
    document_id BIGINT AUTO_INCREMENT,
    document_number VARCHAR(50),
    document_type VARCHAR(50),
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    writer_id BIGINT NOT NULL,
    `status` ENUM('DRAFT', 'PENDING', 'APPROVED', 'REJECTED')
        NOT NULL DEFAULT 'DRAFT',

    PRIMARY KEY (document_id),
    UNIQUE KEY uk_document_number (document_number),

    CONSTRAINT fk_document_writer
        FOREIGN KEY (writer_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 6. 문서별 결재선
CREATE TABLE approval_steps (
    approval_step_id BIGINT AUTO_INCREMENT,
    document_id BIGINT NOT NULL,
    approver_id BIGINT NOT NULL,
    step_order INT NOT NULL,
    `status` ENUM('WAITING', 'APPROVED', 'REJECTED')
        NOT NULL DEFAULT 'WAITING',
    comment VARCHAR(500),

    PRIMARY KEY (approval_step_id),
    UNIQUE KEY uk_document_step (document_id, step_order),

    CONSTRAINT fk_step_document
        FOREIGN KEY (document_id)
        REFERENCES approval_documents(document_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_step_approver
        FOREIGN KEY (approver_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 7. 첨부파일
CREATE TABLE attachments (
    attachment_id BIGINT AUTO_INCREMENT,
    related_type ENUM('NOTICE', 'TASK', 'APPROVAL') NOT NULL,
    related_id BIGINT NOT NULL,
    uploader_id BIGINT NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    stored_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    content_type VARCHAR(100),
    file_size BIGINT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (attachment_id),
    KEY idx_attachment_target (related_type, related_id),

    CONSTRAINT fk_attachment_uploader
        FOREIGN KEY (uploader_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 8. 로그인 감사 기록
CREATE TABLE login_logs (
    login_log_id BIGINT AUTO_INCREMENT,
    employee_id BIGINT,
    login_id VARCHAR(150) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    login_result ENUM('SUCCESS', 'FAILURE') NOT NULL,
    failure_reason VARCHAR(255),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (login_log_id),

    CONSTRAINT fk_login_employee
        FOREIGN KEY (employee_id)
        REFERENCES employees(employee_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB;

SHOW TABLES;
