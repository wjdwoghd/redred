-- MySQL dump 10.13  Distrib 8.0.46, for Win64 (x86_64)
--
-- Host: localhost    Database: company_portal
-- ------------------------------------------------------
-- Server version	8.0.46

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `approval_documents`
--

DROP TABLE IF EXISTS `approval_documents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `approval_documents` (
  `document_id` bigint NOT NULL AUTO_INCREMENT,
  `document_number` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `document_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `title` varchar(200) COLLATE utf8mb4_unicode_ci NOT NULL,
  `content` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `writer_id` bigint NOT NULL,
  `status` enum('DRAFT','PENDING','APPROVED','REJECTED') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'DRAFT',
  PRIMARY KEY (`document_id`),
  UNIQUE KEY `uk_document_number` (`document_number`),
  KEY `fk_document_writer` (`writer_id`),
  CONSTRAINT `fk_document_writer` FOREIGN KEY (`writer_id`) REFERENCES `employees` (`employee_id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `approval_documents`
--

LOCK TABLES `approval_documents` WRITE;
/*!40000 ALTER TABLE `approval_documents` DISABLE KEYS */;
/*!40000 ALTER TABLE `approval_documents` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `approval_steps`
--

DROP TABLE IF EXISTS `approval_steps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `approval_steps` (
  `approval_step_id` bigint NOT NULL AUTO_INCREMENT,
  `document_id` bigint NOT NULL,
  `approver_id` bigint NOT NULL,
  `step_order` int NOT NULL,
  `status` enum('WAITING','APPROVED','REJECTED') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'WAITING',
  `comment` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`approval_step_id`),
  UNIQUE KEY `uk_document_step` (`document_id`,`step_order`),
  KEY `fk_step_approver` (`approver_id`),
  CONSTRAINT `fk_step_approver` FOREIGN KEY (`approver_id`) REFERENCES `employees` (`employee_id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `fk_step_document` FOREIGN KEY (`document_id`) REFERENCES `approval_documents` (`document_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `approval_steps`
--

LOCK TABLES `approval_steps` WRITE;
/*!40000 ALTER TABLE `approval_steps` DISABLE KEYS */;
/*!40000 ALTER TABLE `approval_steps` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `attachments`
--

DROP TABLE IF EXISTS `attachments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `attachments` (
  `attachment_id` bigint NOT NULL AUTO_INCREMENT,
  `related_type` enum('NOTICE','TASK','APPROVAL','RESOURCE','DEPARTMENT') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `related_id` bigint NOT NULL,
  `title` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `uploader_id` bigint NOT NULL,
  `original_name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `stored_name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `file_path` varchar(500) COLLATE utf8mb4_unicode_ci NOT NULL,
  `content_type` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `file_size` bigint DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`attachment_id`),
  KEY `idx_attachment_target` (`related_type`,`related_id`),
  KEY `fk_attachment_uploader` (`uploader_id`),
  CONSTRAINT `fk_attachment_uploader` FOREIGN KEY (`uploader_id`) REFERENCES `employees` (`employee_id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=48 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `attachments`
--

LOCK TABLES `attachments` WRITE;
/*!40000 ALTER TABLE `attachments` DISABLE KEYS */;
/*!40000 ALTER TABLE `attachments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `department`
--

DROP TABLE IF EXISTS `department`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `department` (
  `department_id` bigint NOT NULL AUTO_INCREMENT,
  `department_name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `extension_number` varchar(10) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`department_id`),
  UNIQUE KEY `uk_department_name` (`department_name`),
  UNIQUE KEY `uk_department_extension` (`extension_number`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `department`
--

LOCK TABLES `department` WRITE;
/*!40000 ALTER TABLE `department` DISABLE KEYS */;
INSERT INTO `department` VALUES (1,'인사','1001'),(2,'행정','1002'),(3,'재무','1003'),(4,'기획','1004'),(5,'디자인','1005'),(6,'영업','1006');
/*!40000 ALTER TABLE `department` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `employees`
--

DROP TABLE IF EXISTS `employees`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `employees` (
  `employee_id` bigint NOT NULL AUTO_INCREMENT,
  `employee_number` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `name` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL,
  `phone` varchar(30) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `department_id` bigint DEFAULT NULL,
  `manager_id` bigint DEFAULT NULL,
  `position` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role` enum('USER','MANAGER','ADMIN') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'USER',
  `joined_date` date DEFAULT NULL,
  PRIMARY KEY (`employee_id`),
  UNIQUE KEY `uk_employee_number` (`employee_number`),
  UNIQUE KEY `uk_employee_email` (`email`),
  KEY `fk_employee_department` (`department_id`),
  KEY `fk_employee_manager` (`manager_id`),
  CONSTRAINT `fk_employee_department` FOREIGN KEY (`department_id`) REFERENCES `department` (`department_id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_employee_manager` FOREIGN KEY (`manager_id`) REFERENCES `employees` (`employee_id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `employees`
--

LOCK TABLES `employees` WRITE;
/*!40000 ALTER TABLE `employees` DISABLE KEYS */;
INSERT INTO `employees` VALUES (1,'CT2026001','CortisAdmin!26','고티스','ct2026001@cortis.local',NULL,NULL,NULL,'총관리자','ADMIN','2017-03-02'),(2,'CT2026002','Manager01!26','김민혁','ct2026002@cortis.local',NULL,1,1,'팀장','MANAGER','2018-04-16'),(3,'CT2026003','Manager02!26','김윤호','ct2026003@cortis.local',NULL,2,1,'팀장','MANAGER','2018-07-09'),(4,'CT2026004','Manager03!26','손강훈','ct2026004@cortis.local',NULL,3,1,'팀장','MANAGER','2019-02-11'),(5,'CT2026005','Manager04!26','임재형','ct2026005@cortis.local',NULL,4,1,'팀장','MANAGER','2019-06-24'),(6,'CT2026006','Manager05!26','정재홍','ct2026006@cortis.local',NULL,5,1,'팀장','MANAGER','2020-01-13'),(7,'CT2026007','Manager06!26','조하윤','ct2026007@cortis.local',NULL,6,1,'팀장','MANAGER','2020-05-18'),(8,'CT2026008','User08!26','박서연','ct2026008@cortis.local',NULL,1,2,'대리','USER','2021-03-08'),(9,'CT2026009','User09!26','이준혁','ct2026009@cortis.local',NULL,1,2,'사원','USER','2024-01-15'),(10,'CT2026010','User10!26','최유진','ct2026010@cortis.local',NULL,1,2,'사원','USER','2025-07-01'),(11,'CT2026011','User11!26','한지우','ct2026011@cortis.local',NULL,2,3,'대리','USER','2021-06-14'),(12,'CT2026012','User12!26','오민석','ct2026012@cortis.local',NULL,2,3,'사원','USER','2023-09-04'),(13,'CT2026013','User13!26','서예린','ct2026013@cortis.local',NULL,2,3,'사원','USER','2025-02-17'),(14,'CT2026014','User14!26','강현우','ct2026014@cortis.local',NULL,3,4,'대리','USER','2020-11-02'),(15,'CT2026015','User15!26','문채원','ct2026015@cortis.local',NULL,3,4,'사원','USER','2023-04-10'),(16,'CT2026016','User16!26','배도윤','ct2026016@cortis.local',NULL,3,4,'사원','USER','2025-08-04'),(17,'CT2026017','User17!26','신가은','ct2026017@cortis.local',NULL,4,5,'대리','USER','2021-01-18'),(18,'CT2026018','User18!26','유승민','ct2026018@cortis.local',NULL,4,5,'사원','USER','2023-12-11'),(19,'CT2026019','User19!26','백수아','ct2026019@cortis.local',NULL,4,5,'사원','USER','2026-01-05'),(20,'CT2026020','User20!26','장태현','ct2026020@cortis.local',NULL,5,6,'대리','USER','2020-08-24'),(21,'CT2026021','User21!26','노하린','ct2026021@cortis.local',NULL,5,6,'사원','USER','2024-03-18'),(22,'CT2026022','User22!26','권민재','ct2026022@cortis.local',NULL,5,6,'사원','USER','2025-11-03'),(23,'CT2026023','User23!26','송지안','ct2026023@cortis.local',NULL,6,7,'대리','USER','2021-09-06'),(24,'CT2026024','User24!26','윤성호','ct2026024@cortis.local',NULL,6,7,'사원','USER','2024-06-10'),(25,'CT2026025','User25!26','홍나연','ct2026025@cortis.local',NULL,6,7,'사원','USER','2026-03-02');
/*!40000 ALTER TABLE `employees` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_logs`
--

DROP TABLE IF EXISTS `login_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `login_logs` (
  `login_log_id` bigint NOT NULL AUTO_INCREMENT,
  `employee_id` bigint DEFAULT NULL,
  `login_id` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ip_address` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `user_agent` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `login_result` enum('SUCCESS','FAILURE') COLLATE utf8mb4_unicode_ci NOT NULL,
  `failure_reason` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`login_log_id`),
  KEY `fk_login_employee` (`employee_id`),
  CONSTRAINT `fk_login_employee` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`employee_id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=192 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_logs`
--

LOCK TABLES `login_logs` WRITE;
/*!40000 ALTER TABLE `login_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `login_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `notices`
--

DROP TABLE IF EXISTS `notices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `notices` (
  `notice_id` bigint NOT NULL AUTO_INCREMENT,
  `title` varchar(200) COLLATE utf8mb4_unicode_ci NOT NULL,
  `content` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `author_id` bigint NOT NULL,
  PRIMARY KEY (`notice_id`),
  KEY `fk_notice_author` (`author_id`),
  CONSTRAINT `fk_notice_author` FOREIGN KEY (`author_id`) REFERENCES `employees` (`employee_id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=50 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `notices`
--

LOCK TABLES `notices` WRITE;
/*!40000 ALTER TABLE `notices` DISABLE KEYS */;
INSERT INTO `notices` VALUES (1,'Cortis 사내 포털 이용 안내','Cortis 사내 포털의 주요 메뉴와 이용 방법을 안내합니다.',1),(2,'사내 계정 관리 안내','사내 계정은 본인만 사용하고 계정 정보를 안전하게 관리해 주세요.',2),(3,'정보보안 교육 일정 안내','전 임직원 대상 정보보안 교육 일정을 확인해 주세요.',2),(4,'사내 네트워크 점검 안내','안정적인 서비스 운영을 위한 사내 네트워크 점검이 예정되어 있습니다.',3),(5,'분기별 예산 자료 제출 안내','각 부서는 분기별 예산 집행 자료를 기한 내 제출해 주세요.',4),(6,'하반기 사업계획 작성 일정','부서별 하반기 사업계획과 주요 일정을 작성해 제출해 주세요.',5),(7,'브랜드 디자인 가이드 안내','최신 브랜드 디자인 가이드를 확인하고 업무에 적용해 주세요.',6),(8,'고객정보 취급 유의사항','고객정보는 승인된 업무 목적에 한해 취급해 주세요.',7),(9,'전자결재 이용 안내','휴가 신청과 지출 결의는 전자결재 메뉴를 이용해 주세요.',1),(10,'연휴 비상연락망 안내','연휴 기간 부서별 비상연락망과 근무 일정을 확인해 주세요.',2),(11,'공용 회의실 이용 안내','회의실 예약 시간을 준수하고 사용 후 비품을 정리해 주세요.',3),(12,'외부 파일 등록 안내','외부 파일을 등록할 때 파일명과 내용을 확인해 주세요.',1);
/*!40000 ALTER TABLE `notices` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tasks`
--

DROP TABLE IF EXISTS `tasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tasks` (
  `task_id` bigint NOT NULL AUTO_INCREMENT,
  `title` varchar(200) COLLATE utf8mb4_unicode_ci NOT NULL,
  `creator_id` bigint NOT NULL,
  `assignee_id` bigint DEFAULT NULL,
  `department_id` bigint DEFAULT NULL,
  `status` enum('TODO','IN_PROGRESS','DONE','HOLD') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'TODO',
  `priority` enum('LOW','NORMAL','HIGH','URGENT') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'NORMAL',
  `start_date` date DEFAULT NULL,
  `due_date` date DEFAULT NULL,
  PRIMARY KEY (`task_id`),
  KEY `fk_task_creator` (`creator_id`),
  KEY `fk_task_assignee` (`assignee_id`),
  KEY `fk_task_department` (`department_id`),
  CONSTRAINT `fk_task_assignee` FOREIGN KEY (`assignee_id`) REFERENCES `employees` (`employee_id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_task_creator` FOREIGN KEY (`creator_id`) REFERENCES `employees` (`employee_id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `fk_task_department` FOREIGN KEY (`department_id`) REFERENCES `department` (`department_id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tasks`
--

LOCK TABLES `tasks` WRITE;
/*!40000 ALTER TABLE `tasks` DISABLE KEYS */;
/*!40000 ALTER TABLE `tasks` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-08-29 20:58:31
