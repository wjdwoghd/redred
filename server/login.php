<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
session_start();
require_once __DIR__ . '/../database/db.php';

$error = "";

function write_login_log(mysqli $conn, ?int $employee_id, string $login_id, string $login_result, ?string $failure_reason = null): void
{
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? '';
    $user_agent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);
    $stmt = $conn->prepare("INSERT INTO login_logs (employee_id, login_id, ip_address, user_agent, login_result, failure_reason) VALUES (?, ?, ?, ?, ?, ?)");

    if (!$stmt) {
        return;
    }

    $stmt->bind_param("isssss", $employee_id, $login_id, $ip_address, $user_agent, $login_result, $failure_reason);
    $stmt->execute();
    $stmt->close();
}

if (isset($_GET['employee_number']) || isset($_GET['password'])) {

    $employee_number = $_GET['employee_number'] ?? '';
    $password = $_GET['password'] ?? '';

    $sql = "SELECT * FROM employees WHERE employee_number = '$employee_number' AND password = '$password'";
    $result = $conn->query($sql);

    if (!$result) {
        $error = "로그인 처리 중 시스템 오류가 발생했습니다. DB 오류: " . $conn->error;
        write_login_log($conn, null, $employee_number, "FAILURE", $error);
    } elseif ($result->num_rows >= 1) {


        $user = $result->fetch_assoc();
        write_login_log($conn, (int) $user['employee_id'], $employee_number, "SUCCESS", null);

        $_SESSION['employee_id'] = $user['employee_id'];
        $_SESSION['employee_number'] = $user['employee_number'];
        $_SESSION['name'] = $user['name'];
        $_SESSION['role'] = $user['role'];

        header("Location: index.php");
        exit;
    }

    if ($error === "") {
        $error = "사번 또는 비밀번호가 올바르지 않습니다.";
        write_login_log($conn, null, $employee_number, "FAILURE", $error);
    }
}
?>

<!DOCTYPE html>
<html lang="ko">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>임직원 로그인 | Cortis</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;

    font-family: Arial, "Malgun Gothic", sans-serif;

    background: #f3f6fb;

    display: flex;
    justify-content: center;
    align-items: center;

    padding: 30px;
}


/* 로그인 박스 */
.login-box {
    width: 500px;

    background: #ffffff;

    padding: 45px 50px 40px;

    border-radius: 16px;

    border: 1px solid #e5e7eb;

    box-shadow: 0 12px 35px rgba(15, 23, 42, 0.10);
}


/* 로고 영역 */
.logo-area {
    width: 100%;

    display: flex;
    justify-content: center;
    align-items: center;

    margin-bottom: 30px;
}


/* 회사 로고 */
.login-logo {
    display: block;

    width: 380px;
    max-width: 100%;
    height: auto;

    object-fit: contain;
}


/* 제목 */
h2 {
    margin: 0 0 35px;

    text-align: center;

    font-size: 26px;
    font-weight: 700;

    color: #172033;
}


/* 입력 영역 */
.form-group {
    margin-bottom: 20px;
}


/* 라벨 */
label {
    display: block;

    margin-bottom: 8px;

    font-size: 14px;
    font-weight: 600;

    color: #374151;
}


/* 입력창 */
input {
    width: 100%;

    height: 48px;

    padding: 0 15px;

    background: #f9fafc;

    border: 1px solid #d7dce3;

    border-radius: 8px;

    font-size: 14px;

    color: #111827;

    outline: none;

    transition: 0.2s;
}


input::placeholder {
    color: #a0a7b2;
}


/* 입력창 선택 */
input:focus {
    background: #ffffff;

    border-color: #155eef;

    box-shadow: 0 0 0 3px rgba(21, 94, 239, 0.10);
}


/* 로그인 버튼 */
button {
    width: 100%;

    height: 50px;

    margin-top: 8px;

    background: #155eef;

    color: #ffffff;

    border: none;

    border-radius: 8px;

    font-size: 15px;
    font-weight: 600;

    cursor: pointer;

    transition: 0.2s;
}


button:hover {
    background: #0f4ed8;

    box-shadow: 0 6px 15px rgba(21, 94, 239, 0.22);
}


/* 회원가입 */
.signup {
    margin-top: 30px;

    padding-top: 24px;

    border-top: 1px solid #edf0f4;

    text-align: center;

    font-size: 14px;

    color: #6b7280;
}


.signup a {
    margin-left: 6px;

    color: #155eef;

    font-weight: 600;

    text-decoration: none;
}


.signup a:hover {
    text-decoration: underline;
}


/* 하단 */
.footer {
    margin-top: 25px;

    text-align: center;

    font-size: 11px;

    color: #a0a7b2;
}


/* 모바일 */
@media (max-width: 600px) {

    body {
        padding: 20px;
    }

    .login-box {
        width: 100%;
        padding: 35px 25px;
    }

    .login-logo {
        width: 100%;
    }
}

</style>
<link rel="stylesheet" href="logo.css">

</head>


<body>

<div class="login-box">


    <!-- 회사 로고 -->
    <div class="logo-area">

        <a class="cortis-logo-link" href="index.php" aria-label="Cortis 홈">
            <img
                src="Cortis_로고.png"
                alt="Cortis"
                class="login-logo"
            >
        </a>

    </div>


    <!-- 제목 -->
    <h2>임직원 로그인</h2>
		<?php if (!empty($error)) : ?>
		<p style="color:red; text-align:center;">
    <?= htmlspecialchars($error) ?>
		</p>
		<?php endif; ?>

    <!-- 로그인 폼 -->
    <form method="get" action="">

        <div class="form-group">

            <label for="employee_number">
                사번
            </label>

            <input
                type="text"
                id="employee_number"
                name="employee_number"
                placeholder="사번을 입력하세요"
                autocomplete="username"
                required
            >

        </div>


        <div class="form-group">

            <label for="password">
                비밀번호
            </label>

            <input
                type="password"
                id="password"
                name="password"
                placeholder="비밀번호를 입력하세요"
                autocomplete="current-password"
                required
            >

        </div>


        <button type="submit">
            로그인
        </button>

    </form>


    <!-- 회원가입 -->
    <div class="signup">

        계정이 없으신가요?

        <a href="signup.php">
            회원가입
        </a>

    </div>


    <!-- 하단 -->
    <div class="footer">
        © 2026 Cortis. Company Internal Portal
    </div>


</div>

</body>

</html>
