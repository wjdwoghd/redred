<?php
require_once __DIR__ . '/../database/db.php';

$message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $employee_number = $_POST['employee_number'];
    $name = $_POST['name'];
    $email = $_POST['email'];
    $position = $_POST['position'];
    $password = $_POST['password'];

    $check = $conn->prepare("SELECT employee_id FROM employees WHERE employee_number = ? OR email = ?");
    $check->bind_param("ss", $employee_number, $email);
    $check->execute();
    $result = $check->get_result();

    if ($result->num_rows > 0) {

        $message = "이미 존재하는 사번 또는 이메일입니다.";

    } else {

        $stmt = $conn->prepare("
            INSERT INTO employees
            (employee_number, password, name, email, position, role, joined_date)
            VALUES (?, ?, ?, ?, ?, 'USER', CURDATE())
        ");

        $stmt->bind_param(
            "sssss",
            $employee_number,
            $password,
            $name,
            $email,
            $position
        );

        if ($stmt->execute()) {

            header("Location: login.php");
            exit;

        } else {

            $message = "회원가입에 실패했습니다.";

        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Sign Up | Cortis</title>

<style>
body {
    margin: 0;
    font-family: Arial, "Malgun Gothic", sans-serif;
    background: #f4f6f8;
}

.signup-box {
    width: 420px;
    margin: 70px auto;
    background: white;
    padding: 35px;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}

h2 {
    text-align: center;
    margin-bottom: 30px;
}

label {
    display: block;
    margin-top: 15px;
}

input {
    width: 100%;
    padding: 12px;
    margin-top: 7px;
    box-sizing: border-box;
}

button {
    width: 100%;
    padding: 13px;
    margin-top: 25px;
    background: #2563eb;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
}

.login {
    text-align: center;
    margin-top: 25px;
}

.login a {
    color: #2563eb;
    text-decoration: none;
}
</style>
<link rel="stylesheet" href="logo.css">

</head>

<body>

<div class="signup-box">

    <a class="cortis-logo-link cortis-logo-link--card" href="index.php" aria-label="Cortis 홈">
        <img class="cortis-logo-image" src="Cortis_로고.png" alt="Cortis">
    </a>

    <h2>임직원 회원가입</h2>
    <?php if (!empty($message)) : ?>

    <p style="color:red; text-align:center;">
    <?= htmlspecialchars($message) ?>
    </p>

<?php endif; ?>
    <form method="post" action="">

        <label>사번</label>
        <input
            type="text"
            name="employee_number"
            placeholder="사번을 입력하세요"
            required
        >

        <label>이름</label>
        <input
            type="text"
            name="name"
            placeholder="이름을 입력하세요"
            required
        >

        <label>이메일</label>
        <input
            type="email"
            name="email"
            placeholder="이메일을 입력하세요"
            required
        >

        <label>직급</label>
        <input
            type="text"
            name="position"
            placeholder="예: 사원"
        >

        <label>비밀번호</label>
        <input
            type="password"
            name="password"
            placeholder="비밀번호를 입력하세요"
            required
        >

        <button type="submit">
            회원가입
        </button>

    </form>

    <div class="login">

        <p>이미 계정이 있으신가요?</p>

        <a href="login.php">
            로그인
        </a>

    </div>

</div>

</body>
</html>
