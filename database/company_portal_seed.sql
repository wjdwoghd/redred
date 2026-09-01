-- Cortis 사내 포털 초기 데이터
-- 대상 DB: company_portal (MariaDB 11.x)
-- 실행 전제: company_portal_structure.sql로 8개 테이블이 생성되어 있어야 합니다.
-- 주의: 기존 데이터를 삭제하지 않는 1회 실행용 seed 파일입니다.

USE company_portal;

-- 부서별 내선번호를 부서 정보에 저장하기 위한 필드
ALTER TABLE department
    ADD COLUMN IF NOT EXISTS extension_number VARCHAR(10) NULL
    AFTER department_name;

START TRANSACTION;

-- 1. 부서: PHP의 department_data.php 순서와 동일
INSERT INTO department
    (department_id, department_name, extension_number)
VALUES
    (1, '인사',   '1001'),
    (2, '행정',   '1002'),
    (3, '재무',   '1003'),
    (4, '기획',   '1004'),
    (5, '디자인', '1005'),
    (6, '영업',   '1006');

-- 2-1. 총관리자 및 부서별 관리자
-- 삽입 직후 아래 UPDATE 문에서 계정별 평문 비밀번호를 지정합니다.
INSERT INTO employees
    (employee_id, employee_number, password, name, email, phone,
     department_id, manager_id, `position`, `role`, joined_date)
VALUES
    (1, 'CT2026001', 'Cortis!2026',
     '고티스', 'ct2026001@cortis.local', NULL, NULL, NULL, '총관리자', 'ADMIN', '2017-03-02'),
    (2, 'CT2026002', 'Cortis!2026',
     '김민혁', 'ct2026002@cortis.local', NULL, 1, 1, '팀장', 'MANAGER', '2018-04-16'),
    (3, 'CT2026003', 'Cortis!2026',
     '김윤호', 'ct2026003@cortis.local', NULL, 2, 1, '팀장', 'MANAGER', '2018-07-09'),
    (4, 'CT2026004', 'Cortis!2026',
     '손강훈', 'ct2026004@cortis.local', NULL, 3, 1, '팀장', 'MANAGER', '2019-02-11'),
    (5, 'CT2026005', 'Cortis!2026',
     '임재형', 'ct2026005@cortis.local', NULL, 4, 1, '팀장', 'MANAGER', '2019-06-24'),
    (6, 'CT2026006', 'Cortis!2026',
     '정재홍', 'ct2026006@cortis.local', NULL, 5, 1, '팀장', 'MANAGER', '2020-01-13'),
    (7, 'CT2026007', 'Cortis!2026',
     '조하윤', 'ct2026007@cortis.local', NULL, 6, 1, '팀장', 'MANAGER', '2020-05-18');

-- 2-2. 부서별 직원 3명: 대리 1명, 사원 2명
INSERT INTO employees
    (employee_id, employee_number, password, name, email, phone,
     department_id, manager_id, `position`, `role`, joined_date)
VALUES
    (8, 'CT2026008', 'Cortis!2026',
     '박서연', 'ct2026008@cortis.local', NULL, 1, 2, '대리', 'USER', '2021-03-08'),
    (9, 'CT2026009', 'Cortis!2026',
     '이준혁', 'ct2026009@cortis.local', NULL, 1, 2, '사원', 'USER', '2024-01-15'),
    (10, 'CT2026010', 'Cortis!2026',
     '최유진', 'ct2026010@cortis.local', NULL, 1, 2, '사원', 'USER', '2025-07-01'),

    (11, 'CT2026011', 'Cortis!2026',
     '한지우', 'ct2026011@cortis.local', NULL, 2, 3, '대리', 'USER', '2021-06-14'),
    (12, 'CT2026012', 'Cortis!2026',
     '오민석', 'ct2026012@cortis.local', NULL, 2, 3, '사원', 'USER', '2023-09-04'),
    (13, 'CT2026013', 'Cortis!2026',
     '서예린', 'ct2026013@cortis.local', NULL, 2, 3, '사원', 'USER', '2025-02-17'),

    (14, 'CT2026014', 'Cortis!2026',
     '강현우', 'ct2026014@cortis.local', NULL, 3, 4, '대리', 'USER', '2020-11-02'),
    (15, 'CT2026015', 'Cortis!2026',
     '문채원', 'ct2026015@cortis.local', NULL, 3, 4, '사원', 'USER', '2023-04-10'),
    (16, 'CT2026016', 'Cortis!2026',
     '배도윤', 'ct2026016@cortis.local', NULL, 3, 4, '사원', 'USER', '2025-08-04'),

    (17, 'CT2026017', 'Cortis!2026',
     '신가은', 'ct2026017@cortis.local', NULL, 4, 5, '대리', 'USER', '2021-01-18'),
    (18, 'CT2026018', 'Cortis!2026',
     '유승민', 'ct2026018@cortis.local', NULL, 4, 5, '사원', 'USER', '2023-12-11'),
    (19, 'CT2026019', 'Cortis!2026',
     '백수아', 'ct2026019@cortis.local', NULL, 4, 5, '사원', 'USER', '2026-01-05'),

    (20, 'CT2026020', 'Cortis!2026',
     '장태현', 'ct2026020@cortis.local', NULL, 5, 6, '대리', 'USER', '2020-08-24'),
    (21, 'CT2026021', 'Cortis!2026',
     '노하린', 'ct2026021@cortis.local', NULL, 5, 6, '사원', 'USER', '2024-03-18'),
    (22, 'CT2026022', 'Cortis!2026',
     '권민재', 'ct2026022@cortis.local', NULL, 5, 6, '사원', 'USER', '2025-11-03'),

    (23, 'CT2026023', 'Cortis!2026',
     '송지안', 'ct2026023@cortis.local', NULL, 6, 7, '대리', 'USER', '2021-09-06'),
    (24, 'CT2026024', 'Cortis!2026',
     '윤성호', 'ct2026024@cortis.local', NULL, 6, 7, '사원', 'USER', '2024-06-10'),
    (25, 'CT2026025', 'Cortis!2026',
     '홍나연', 'ct2026025@cortis.local', NULL, 6, 7, '사원', 'USER', '2026-03-02');

-- 의도적으로 취약하게 구성한 실습용 평문 비밀번호
-- 총관리자: CortisAdmin!26
-- 부서 관리자: Manager01!26 ~ Manager06!26
-- 일반 직원: User08!26 ~ User25!26
UPDATE employees
SET password = CASE
    WHEN `role` = 'ADMIN' THEN 'CortisAdmin!26'
    WHEN `role` = 'MANAGER' THEN CONCAT('Manager', LPAD(department_id, 2, '0'), '!26')
    WHEN `role` = 'USER' THEN CONCAT('User', RIGHT(employee_number, 2), '!26')
    ELSE 'CortisDefault!26'
END;

-- 3. 공지사항 12건
INSERT INTO notices (notice_id, title, content, author_id) VALUES
    (1, 'Cortis 사내 포털 정식 오픈 안내',
     '임직원의 원활한 업무 처리를 위한 Cortis 사내 포털이 정식 오픈되었습니다.', 1),
    (2, '2026년 하반기 정보보안 교육 안내',
     '전 임직원을 대상으로 정보보안 및 개인정보보호 교육을 실시합니다.', 2),
    (3, '비밀번호 변경 정책 시행 안내',
     '계정 보호를 위해 초기 비밀번호를 변경하고 타 서비스와 동일한 비밀번호를 사용하지 마시기 바랍니다.', 2),
    (4, '사내 네트워크 정기 점검 안내',
     '안정적인 서비스 운영을 위해 사내 네트워크 정기 점검을 진행합니다.', 3),
    (5, '분기별 예산 집행 자료 제출 요청',
     '각 부서는 분기별 예산 집행 내역을 기한 내 제출해 주시기 바랍니다.', 4),
    (6, '하반기 사업계획 작성 일정 안내',
     '부서별 하반기 사업계획과 핵심성과지표를 작성하여 제출해 주시기 바랍니다.', 5),
    (7, '브랜드 디자인 가이드 개정 안내',
     '새롭게 개정된 사내 브랜드 디자인 가이드를 자료실에서 확인할 수 있습니다.', 6),
    (8, '고객정보 취급 시 유의사항',
     '고객정보는 업무 목적으로만 이용하고 승인되지 않은 외부 전송을 금지합니다.', 7),
    (9, '전자결재 시스템 사용 안내',
     '휴가신청서와 지출결의서는 전자결재 메뉴를 통해 제출해 주시기 바랍니다.', 1),
    (10, '추석 연휴 근무 일정 안내',
     '추석 연휴 기간의 부서별 당직 및 비상연락망을 확인해 주시기 바랍니다.', 2),
    (11, '공용 회의실 이용 수칙 안내',
     '회의실 예약 시간을 준수하고 사용 후 장비와 비품을 정리해 주시기 바랍니다.', 3),
    (12, '외부 파일 업로드 보안정책 안내',
     '업무 자료 업로드 전 파일 확장자와 악성코드 검사 결과를 확인해 주시기 바랍니다.', 1);

-- 4. 업무 24건: 부서별 4건
INSERT INTO tasks
    (task_id, title, creator_id, assignee_id, department_id,
     `status`, priority, start_date, due_date)
VALUES
    (1,  '신규 입사자 인사정보 등록',       2,  8, 1, 'DONE',        'HIGH',   '2026-08-03', '2026-08-05'),
    (2,  '하반기 정보보안 교육 참석자 취합', 2,  9, 1, 'IN_PROGRESS', 'NORMAL', '2026-08-24', '2026-09-02'),
    (3,  '연차 사용 현황 정리',             2, 10, 1, 'TODO',        'NORMAL', '2026-08-27', '2026-09-04'),
    (4,  '인사 규정 개정안 검토',           2,  8, 1, 'HOLD',        'LOW',    '2026-08-20', '2026-09-15'),

    (5,  '공용 회의실 예약 현황 점검',       3, 11, 2, 'DONE',        'LOW',    '2026-08-10', '2026-08-12'),
    (6,  '사무용 비품 재고 조사',           3, 12, 2, 'IN_PROGRESS', 'NORMAL', '2026-08-25', '2026-09-01'),
    (7,  '사내 행사 장소 섭외',             3, 13, 2, 'TODO',        'HIGH',   '2026-08-27', '2026-09-08'),
    (8,  '문서 보존기간 목록 정비',         3, 11, 2, 'TODO',        'NORMAL', '2026-08-27', '2026-09-10'),

    (9,  '8월 지출결의서 검토',              4, 14, 3, 'IN_PROGRESS', 'HIGH',   '2026-08-24', '2026-08-31'),
    (10, '분기별 예산 집행 내역 정리',       4, 15, 3, 'TODO',        'NORMAL', '2026-08-27', '2026-09-07'),
    (11, '거래처 세금계산서 대조',           4, 16, 3, 'DONE',        'HIGH',   '2026-08-17', '2026-08-21'),
    (12, '하반기 비용 절감안 작성',          4, 14, 3, 'HOLD',        'LOW',    '2026-08-20', '2026-09-18'),

    (13, '신규 서비스 기획안 작성',          5, 17, 4, 'IN_PROGRESS', 'HIGH',   '2026-08-24', '2026-09-11'),
    (14, '경쟁사 기능 비교 분석',            5, 18, 4, 'DONE',        'NORMAL', '2026-08-10', '2026-08-19'),
    (15, '고객 설문 문항 검토',              5, 19, 4, 'TODO',        'NORMAL', '2026-08-28', '2026-09-04'),
    (16, '3분기 핵심성과지표 정리',          5, 17, 4, 'TODO',        'URGENT', '2026-08-27', '2026-09-01'),

    (17, '포털 메인 화면 시안 수정',         6, 20, 5, 'IN_PROGRESS', 'HIGH',   '2026-08-24', '2026-09-03'),
    (18, '브랜드 아이콘 세트 제작',          6, 21, 5, 'TODO',        'NORMAL', '2026-08-27', '2026-09-14'),
    (19, '발표자료 템플릿 검수',             6, 22, 5, 'DONE',        'NORMAL', '2026-08-17', '2026-08-21'),
    (20, '모바일 화면 사용성 점검',          6, 20, 5, 'HOLD',        'LOW',    '2026-08-20', '2026-09-16'),

    (21, '신규 고객사 제안서 작성',          7, 23, 6, 'IN_PROGRESS', 'URGENT', '2026-08-25', '2026-09-02'),
    (22, '8월 영업 실적 집계',               7, 24, 6, 'TODO',        'HIGH',   '2026-08-27', '2026-09-01'),
    (23, '고객사 미팅 일정 조율',            7, 25, 6, 'DONE',        'NORMAL', '2026-08-18', '2026-08-20'),
    (24, '잠재 고객 목록 정비',              7, 23, 6, 'TODO',        'NORMAL', '2026-08-28', '2026-09-09');

-- 5. 전자결재 문서 12건
INSERT INTO approval_documents
    (document_id, document_number, document_type, title, content, writer_id, `status`)
VALUES
    (1,  'HR-2026-001',  '휴가신청서', '2026년 9월 연차 사용 신청',
     '개인 일정으로 2026년 9월 4일 연차 사용을 신청합니다.', 8, 'APPROVED'),
    (2,  'HR-2026-002',  '교육신청서', '개인정보보호 실무교육 신청',
     '업무 역량 향상을 위해 개인정보보호 실무교육 참석을 신청합니다.', 9, 'PENDING'),
    (3,  'GA-2026-001',  '구매요청서', '사무용 의자 추가 구매 요청',
     '신규 입사자 좌석 배치를 위해 사무용 의자 3개 구매를 요청합니다.', 11, 'APPROVED'),
    (4,  'GA-2026-002',  '지출결의서', '사내 행사 준비물 구매 비용',
     '사내 행사 진행에 필요한 명찰과 안내물 구매 비용을 결의합니다.', 12, 'REJECTED'),
    (5,  'FI-2026-001',  '지출결의서', '회계 프로그램 연간 이용료 지급',
     '회계 프로그램 연간 라이선스 갱신 비용 지급을 요청합니다.', 14, 'PENDING'),
    (6,  'FI-2026-002',  '업무보고서', '2026년 8월 예산 집행 현황 보고',
     '2026년 8월 부서별 예산 집행 현황과 주요 증감 사유를 보고합니다.', 15, 'DRAFT'),
    (7,  'PL-2026-001',  '기획안', '신규 고객지원 서비스 기획안',
     '고객 문의 처리시간 단축을 위한 신규 지원 서비스 도입안을 제안합니다.', 17, 'PENDING'),
    (8,  'PL-2026-002',  '출장신청서', '서비스 조사 목적 국내 출장 신청',
     '유사 서비스 조사와 관계자 미팅을 위한 국내 출장을 신청합니다.', 18, 'APPROVED'),
    (9,  'DS-2026-001',  '구매요청서', '디자인 소프트웨어 라이선스 구매',
     '디자인 업무용 소프트웨어 라이선스 3개 구매를 요청합니다.', 20, 'APPROVED'),
    (10, 'DS-2026-002',  '검토요청서', '브랜드 디자인 가이드 검토 요청',
     '개정된 브랜드 디자인 가이드의 최종 검토와 승인을 요청합니다.', 21, 'PENDING'),
    (11, 'SA-2026-001',  '출장신청서', '부산 고객사 방문 출장 신청',
     '계약 협의를 위한 부산 고객사 방문 출장을 신청합니다.', 23, 'REJECTED'),
    (12, 'SA-2026-002',  '업무보고서', '2026년 8월 영업 실적 보고',
     '2026년 8월 신규 계약과 고객 상담 실적을 보고합니다.', 24, 'DRAFT');

-- 6. 문서별 결재선
INSERT INTO approval_steps
    (approval_step_id, document_id, approver_id, step_order, `status`, comment)
VALUES
    (1,  1, 2, 1, 'APPROVED', '업무 일정 확인 후 승인합니다.'),
    (2,  1, 1, 2, 'APPROVED', '최종 승인합니다.'),
    (3,  2, 2, 1, 'WAITING',  NULL),
    (4,  2, 1, 2, 'WAITING',  NULL),
    (5,  3, 3, 1, 'APPROVED', '구매 필요성을 확인했습니다.'),
    (6,  3, 1, 2, 'APPROVED', '최종 승인합니다.'),
    (7,  4, 3, 1, 'REJECTED', '구매 항목과 금액을 보완해 다시 제출해 주세요.'),
    (8,  5, 4, 1, 'WAITING',  NULL),
    (9,  5, 1, 2, 'WAITING',  NULL),
    (10, 7, 5, 1, 'WAITING',  NULL),
    (11, 7, 1, 2, 'WAITING',  NULL),
    (12, 8, 5, 1, 'APPROVED', '출장 계획을 확인했습니다.'),
    (13, 8, 1, 2, 'APPROVED', '최종 승인합니다.'),
    (14, 9, 6, 1, 'APPROVED', '업무상 필요한 라이선스입니다.'),
    (15, 9, 1, 2, 'APPROVED', '최종 승인합니다.'),
    (16, 10, 6, 1, 'WAITING', NULL),
    (17, 10, 1, 2, 'WAITING', NULL),
    (18, 11, 7, 1, 'REJECTED', '출장 일정과 방문 목적을 구체화해 주세요.');

-- 7. 첨부파일 메타데이터 10건
-- 실제 파일은 별도로 server/uploads/ 경로에 배치해야 합니다.
INSERT INTO attachments
    (attachment_id, related_type, related_id, uploader_id,
     original_name, stored_name, file_path, content_type, file_size, created_at)
VALUES
    (1, 'NOTICE', 2, 2, '2026_정보보안교육_안내.pdf',
     'notice_20260824_001.pdf', 'uploads/notice_20260824_001.pdf',
     'application/pdf', 284216, '2026-08-24 09:15:00'),
    (2, 'NOTICE', 7, 6, 'Cortis_브랜드_가이드.pdf',
     'notice_20260825_002.pdf', 'uploads/notice_20260825_002.pdf',
     'application/pdf', 1524860, '2026-08-25 11:20:00'),
    (3, 'NOTICE', 10, 2, '추석연휴_비상연락망.xlsx',
     'notice_20260826_003.xlsx', 'uploads/notice_20260826_003.xlsx',
     'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 48215, '2026-08-26 14:10:00'),
    (4, 'TASK', 6, 11, '비품재고_조사표.xlsx',
     'task_20260825_001.xlsx', 'uploads/task_20260825_001.xlsx',
     'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 36570, '2026-08-25 16:30:00'),
    (5, 'TASK', 13, 17, '신규서비스_기획안_v1.docx',
     'task_20260825_002.docx', 'uploads/task_20260825_002.docx',
     'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 91642, '2026-08-25 17:05:00'),
    (6, 'TASK', 17, 20, '포털_메인화면_시안.png',
     'task_20260826_003.png', 'uploads/task_20260826_003.png',
     'image/png', 836224, '2026-08-26 10:40:00'),
    (7, 'APPROVAL', 3, 11, '사무용의자_견적서.pdf',
     'approval_20260820_001.pdf', 'uploads/approval_20260820_001.pdf',
     'application/pdf', 194350, '2026-08-20 13:25:00'),
    (8, 'APPROVAL', 5, 14, '회계프로그램_갱신견적.pdf',
     'approval_20260824_002.pdf', 'uploads/approval_20260824_002.pdf',
     'application/pdf', 127884, '2026-08-24 15:10:00'),
    (9, 'APPROVAL', 9, 20, '디자인SW_구매견적서.pdf',
     'approval_20260822_003.pdf', 'uploads/approval_20260822_003.pdf',
     'application/pdf', 220415, '2026-08-22 10:45:00'),
    (10, 'APPROVAL', 11, 23, '부산출장_일정표.docx',
     'approval_20260826_004.docx', 'uploads/approval_20260826_004.docx',
     'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 53680, '2026-08-26 18:20:00');

-- 8. 로그인 감사 기록 40건
INSERT INTO login_logs
    (login_log_id, employee_id, login_id, ip_address, user_agent,
     login_result, failure_reason, created_at)
VALUES
    (1,  1, 'CT2026001', '192.168.10.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-24 08:42:11'),
    (2,  2, 'CT2026002', '192.168.10.21', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-24 08:51:02'),
    (3,  8, 'CT2026008', '192.168.10.22', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-24 08:55:36'),
    (4,  9, 'CT2026009', '192.168.10.23', 'Mozilla/5.0 (X11; Linux x86_64)', 'FAILURE', '비밀번호 불일치', '2026-08-24 09:01:14'),
    (5,  9, 'CT2026009', '192.168.10.23', 'Mozilla/5.0 (X11; Linux x86_64)', 'SUCCESS', NULL, '2026-08-24 09:02:03'),
    (6,  3, 'CT2026003', '192.168.20.11', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 'SUCCESS', NULL, '2026-08-24 09:06:45'),
    (7, 11, 'CT2026011', '192.168.20.12', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-24 09:10:22'),
    (8, 12, 'CT2026012', '192.168.20.13', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-24 09:18:51'),
    (9, NULL, 'CT2026999', '192.168.20.90', 'Mozilla/5.0 (X11; Linux x86_64)', 'FAILURE', '존재하지 않는 사번', '2026-08-24 10:03:17'),
    (10, 4, 'CT2026004', '192.168.30.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-24 10:20:09'),
    (11, 14, 'CT2026014', '192.168.30.12', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-24 10:25:44'),
    (12, 15, 'CT2026015', '192.168.30.13', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X)', 'FAILURE', '비밀번호 불일치', '2026-08-24 10:31:28'),
    (13, 15, 'CT2026015', '192.168.30.13', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X)', 'SUCCESS', NULL, '2026-08-24 10:33:02'),
    (14, 5, 'CT2026005', '192.168.40.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-25 08:47:39'),
    (15, 17, 'CT2026017', '192.168.40.12', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-25 08:52:15'),
    (16, 18, 'CT2026018', '192.168.40.13', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 'SUCCESS', NULL, '2026-08-25 08:58:42'),
    (17, 19, 'CT2026019', '192.168.40.14', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'FAILURE', '비밀번호 불일치', '2026-08-25 09:05:18'),
    (18, 6, 'CT2026006', '192.168.50.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-25 09:12:55'),
    (19, 20, 'CT2026020', '192.168.50.12', 'Mozilla/5.0 (X11; Linux x86_64)', 'SUCCESS', NULL, '2026-08-25 09:17:21'),
    (20, 21, 'CT2026021', '192.168.50.13', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-25 09:24:06'),
    (21, 22, 'CT2026022', '192.168.50.14', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-25 09:30:49'),
    (22, 7, 'CT2026007', '192.168.60.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-25 09:37:33'),
    (23, 23, 'CT2026023', '192.168.60.12', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 'SUCCESS', NULL, '2026-08-25 09:42:18'),
    (24, 24, 'CT2026024', '192.168.60.13', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'FAILURE', '비밀번호 불일치', '2026-08-25 09:50:27'),
    (25, 24, 'CT2026024', '192.168.60.13', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-25 09:51:10'),
    (26, 25, 'CT2026025', '192.168.60.14', 'Mozilla/5.0 (Linux; Android 16)', 'SUCCESS', NULL, '2026-08-25 10:04:36'),
    (27, 10, 'CT2026010', '192.168.10.24', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-26 08:49:51'),
    (28, 13, 'CT2026013', '192.168.20.14', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-26 08:54:32'),
    (29, 16, 'CT2026016', '192.168.30.14', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-26 09:03:14'),
    (30, 1, 'CT2026001', '192.168.10.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-26 09:16:05'),
    (31, NULL, 'admin', '192.168.10.99', 'Mozilla/5.0 (X11; Linux x86_64)', 'FAILURE', '존재하지 않는 사번', '2026-08-26 11:32:48'),
    (32, NULL, 'administrator', '192.168.10.99', 'Mozilla/5.0 (X11; Linux x86_64)', 'FAILURE', '존재하지 않는 사번', '2026-08-26 11:33:07'),
    (33, 2, 'CT2026002', '192.168.10.21', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-26 13:20:42'),
    (34, 6, 'CT2026006', '192.168.50.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'FAILURE', '비밀번호 불일치', '2026-08-26 14:11:23'),
    (35, 6, 'CT2026006', '192.168.50.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-26 14:12:04'),
    (36, 3, 'CT2026003', '192.168.20.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-27 08:38:19'),
    (37, 4, 'CT2026004', '192.168.30.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-27 08:42:55'),
    (38, 5, 'CT2026005', '192.168.40.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-27 08:47:31'),
    (39, 7, 'CT2026007', '192.168.60.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-27 08:52:26'),
    (40, 1, 'CT2026001', '192.168.10.10', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'SUCCESS', NULL, '2026-08-27 09:01:44');

COMMIT;

-- 9. 입력 결과 검증
SELECT COUNT(*) AS department_count FROM department;
SELECT COUNT(*) AS employee_count FROM employees;
SELECT COUNT(*) AS notice_count FROM notices;
SELECT COUNT(*) AS task_count FROM tasks;
SELECT COUNT(*) AS document_count FROM approval_documents;
SELECT COUNT(*) AS approval_step_count FROM approval_steps;
SELECT COUNT(*) AS attachment_count FROM attachments;
SELECT COUNT(*) AS login_log_count FROM login_logs;

SELECT
    d.department_id,
    d.department_name,
    d.extension_number,
    COUNT(e.employee_id) AS employee_count
FROM department d
LEFT JOIN employees e ON e.department_id = d.department_id
GROUP BY d.department_id, d.department_name, d.extension_number
ORDER BY d.department_id;

SELECT
    e.employee_number,
    e.name,
    COALESCE(d.department_name, '전사') AS department_name,
    e.`position`,
    e.`role`,
    COALESCE(m.name, '-') AS manager_name,
    e.email
FROM employees e
LEFT JOIN department d ON d.department_id = e.department_id
LEFT JOIN employees m ON m.employee_id = e.manager_id
ORDER BY e.employee_id;
