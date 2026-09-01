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


/* 로그인 확인 */

if (!isset($_SESSION["employee_id"])) {
    header("Location: login.php");
    exit;
}


/* 현재 로그인 사용자 */

$logged_in_user_id = $_SESSION["employee_id"];
$keyword = trim((string) ($_GET['keyword'] ?? ''));


/* 자료 목록 조회 */

$sql = "SELECT a.attachment_id, a.related_type, a.related_id, a.title, a.uploader_id, a.original_name, a.stored_name, a.file_path, a.content_type, a.file_size, a.created_at, e.name AS uploader_name FROM attachments a LEFT JOIN employees e ON a.uploader_id = e.employee_id WHERE a.related_type = 'RESOURCE' AND (a.title LIKE '%$keyword%' OR a.original_name LIKE '%$keyword%' OR a.stored_name LIKE '%$keyword%' OR e.name LIKE '%$keyword%') ORDER BY a.created_at DESC";
$result = $conn->query($sql);

if (!$result) {
    die("자료 목록 조회 중 시스템 오류가 발생했습니다. DB 오류: " . $conn->error);
}

?>

<!DOCTYPE html>
<html lang="ko">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>자료실 | Cortis</title>


    <style>

        * {
            box-sizing: border-box;
        }


        body {
            margin: 0;

            font-family: Arial,
                         "Malgun Gothic",
                         sans-serif;

            background: #f4f6f8;

            color: #333;
        }


        /* Header */

        header {
            background: #1f2937;

            color: white;

            padding: 22px 0;
        }


        .header-inner {
            width: 1100px;

            margin: auto;
        }


        .logo {
            font-size: 28px;

            font-weight: bold;
        }


        .subtitle {
            margin-top: 5px;

            font-size: 14px;

            color: #d1d5db;
        }


        /* Navigation */

        nav {
            background: white;

            border-bottom: 1px solid #ddd;
        }


        .nav-inner {
            width: 1100px;

            margin: auto;

            display: flex;

            align-items: center;
        }


        nav a {
            display: block;

            padding: 18px 30px;

            color: #333;

            text-decoration: none;

            font-size: 15px;
        }


        nav a:hover {
            background: #f1f5f9;
        }

        nav a.active {
            color: #2563eb;
            font-weight: bold;
            border-bottom: 3px solid #2563eb;
        }


        .mypage {
            margin-left: auto;

            color: #2563eb;

            font-weight: bold;
        }


        /* Main */

        main {
            width: 1100px;

            margin: 35px auto;
        }


        .page-header {
            background: white;

            padding: 30px;

            border-radius: 8px;

            box-shadow:
                0 2px 8px rgba(0, 0, 0, 0.08);

            margin-bottom: 25px;
        }


        .page-header h1 {
            margin-top: 0;

            margin-bottom: 10px;
        }


        .page-header p {
            color: #666;

            margin-bottom: 0;
        }


        /* Upload button */

        .action-area {
            margin-bottom: 20px;

            text-align: right;
        }


        .button {
            display: inline-block;

            padding: 10px 18px;

            background: #2563eb;

            color: white;

            text-decoration: none;

            border-radius: 6px;

            font-size: 14px;
        }


        .button:hover {
            background: #1d4ed8;
        }


        /* Table */

        .resource-box {
            background: white;

            padding: 30px;

            border-radius: 8px;

            box-shadow:
                0 2px 8px rgba(0, 0, 0, 0.08);
        }


        table {
            width: 100%;

            border-collapse: collapse;
        }


        th {
            background: #f8fafc;

            color: #475569;

            font-weight: 600;

            padding: 14px 10px;

            border-bottom: 2px solid #e5e7eb;
        }


        td {
            padding: 14px 10px;

            border-bottom: 1px solid #e5e7eb;

            text-align: center;

            font-size: 14px;
        }


        td.filename {
            text-align: left;
        }


        .download {
            display: inline-block;

            padding: 6px 12px;

            background: #2563eb;

            color: white;

            text-decoration: none;

            border-radius: 5px;

            font-size: 12px;
        }


        .download:hover {
            background: #1d4ed8;
        }


        .empty {
            padding: 50px;

            color: #94a3b8;

            text-align: center;
        }

        .search-form {
            display: flex;
            gap: 10px;
            margin: 0 0 20px;
        }

        .search-form input {
            flex: 1;
            padding: 12px 14px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font: inherit;
        }

        .search-keyword {
            margin: 0 0 18px;
            color: #475569;
            font-size: 14px;
        }


        /* Footer */

        footer {
            margin-top: 60px;

            background: #1f2937;

            color: #aaa;

            text-align: center;

            padding: 25px;

            font-size: 13px;
        }

    </style>
    <link rel="stylesheet" href="logo.css">

</head>


<body>


<!-- Header -->

<header>

    <div class="header-inner">

        <a class="cortis-logo-link" href="index.php" aria-label="Cortis 홈">
            <img class="cortis-logo-image" src="Cortis_로고.png" alt="Cortis">
        </a>

        <div class="subtitle">
            Company Internal Management System
        </div>

    </div>

</header>


<!-- Navigation -->

<nav>

    <div class="nav-inner">

        <a href="index.php">
            홈
        </a>

        <a href="login.php">
            로그인
        </a>

        <a href="resource.php" class="active">
            자료실
        </a>

        <a href="department.php">
            부서
        </a>

        <a href="notices.php">
            공지사항
        </a>

        <a href="mypage.php" class="mypage">
            My Page
        </a>

    </div>

</nav>


<!-- Main -->

<main>


    <!-- Page Header -->

    <section class="page-header">

        <h1>
            사내 자료실
        </h1>

        <p>
            업무에 필요한 자료와 문서를
            확인하고 다운로드할 수 있습니다.
        </p>

    </section>


    <!-- Upload -->

    <div class="action-area">

        <a href="upload.php" class="button">
            + 자료 등록
        </a>

    </div>


    <!-- Resource List -->

    <section class="resource-box">

        <form class="search-form" method="get" action="resource.php">
            <input type="search" name="keyword" value="<?= $keyword ?>" placeholder="자료명, 등록자, 구분 검색" aria-label="자료 검색어">
            <button type="submit" class="button">검색</button>
        </form>

        <?php if ($keyword !== ''): ?>
            <p class="search-keyword">검색어: <?= $keyword ?></p>
        <?php endif; ?>


        <?php if ($result && $result->num_rows > 0): ?>

            <table>

                <thead>

                    <tr>

                        <th style="width: 10%;">
                            번호
                        </th>

                        <th>
                            파일명
                        </th>

                        <th>
                            제목
                        </th>

                        <th style="width: 15%;">
                            등록자
                        </th>

                        <th style="width: 18%;">
                            등록일
                        </th>

                        <th style="width: 12%;">
                            다운로드
                        </th>

                    </tr>

                </thead>


                <tbody>


                    <?php while ($row = $result->fetch_assoc()): ?>

                        <tr>

                            <td>
                                <?= htmlspecialchars(
                                    (string)$row["attachment_id"]
                                ) ?>
                            </td>


                            <td class="filename">

                                <?= $row["original_name"] ?>

                            </td>


                            <td class="filename">
                                <?= $row["title"] ?: "제목 없음" ?>
                            </td>


                            <td>

                                <?= htmlspecialchars(
                                    $row["uploader_name"] ?? "알 수 없음"
                                ) ?>

                            </td>


                            <td>

                                <?= htmlspecialchars(
                                    date(
                                        "Y-m-d",
                                        strtotime($row["created_at"])
                                    )
                                ) ?>

                            </td>


                            <td>

                                <a
                                    href="download.php?id=<?= urlencode($row["attachment_id"]) ?>"
                                    class="download"
                                >
                                    다운로드
                                </a>

                            </td>

                        </tr>

                    <?php endwhile; ?>


                </tbody>

            </table>


        <?php else: ?>

            <div class="empty">

                등록된 자료가 없습니다.

            </div>

        <?php endif; ?>


    </section>


</main>


<!-- Footer -->

<footer>

    Cortis &copy; 2026

</footer>


</body>

</html>
