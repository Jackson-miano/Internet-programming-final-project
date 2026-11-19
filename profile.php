<?php
require "config.php";
require_login();

$uid = $_SESSION["user_id"];
$errors = [];
$msg = "";

// ---------- Load the logged-in user ----------
$s = $pdo->prepare("SELECT username, first_name, last_name, email, phone, role, created_at FROM users WHERE id = ?");
$s->execute([$uid]);
$user = $s->fetch(PDO::FETCH_ASSOC);
if (!$user) {               // account no longer exists
    session_destroy();
    header("Location: login.php");
    exit;
}
$form = $user;              // values shown in the details form

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $action = $_POST["action"] ?? "";

    // ---------- Update personal details ----------
    if ($action === "details") {
        $form["first_name"] = trim($_POST["fname"] ?? "");
        $form["last_name"]  = trim($_POST["lname"] ?? "");
        $form["email"]      = trim($_POST["email"] ?? "");
        $form["phone"]      = trim($_POST["phone"] ?? "");

        if ($form["first_name"] === "") $errors[] = "First name is required.";
        if ($form["last_name"] === "")  $errors[] = "Last name is required.";
        if (!filter_var($form["email"], FILTER_VALIDATE_EMAIL)) $errors[] = "Enter a valid email address.";
        if (!preg_match('/^\+?[0-9]{9,15}$/', $form["phone"])) $errors[] = "Enter a valid phone number (9-15 digits, may start with +).";

        if (empty($errors)) {
            $c = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id <> ?");
            $c->execute([$form["email"], $uid]);
            if ($c->fetch()) {
                $errors[] = "That email is already used by another account.";
            } else {
                $u = $pdo->prepare("UPDATE users SET first_name = ?, last_name = ?, email = ?, phone = ? WHERE id = ?");
                $u->execute([$form["first_name"], $form["last_name"], $form["email"], $form["phone"], $uid]);
                $_SESSION["first_name"] = $form["first_name"];
                $user = $form;
                $msg = "Profile updated.";
            }
        }
    }

    // ---------- Change password ----------
    elseif ($action === "password") {
        $current = $_POST["current_password"] ?? "";
        $new     = $_POST["new_password"] ?? "";
        $confirm = $_POST["confirm_password"] ?? "";

        $h = $pdo->prepare("SELECT password FROM users WHERE id = ?");
        $h->execute([$uid]);
        $hash = $h->fetchColumn();

        if (!password_verify($current, $hash)) $errors[] = "Your current password is incorrect.";
        if (strlen($new) < 8)                  $errors[] = "The new password must be at least 8 characters.";
        if ($new !== $confirm)                 $errors[] = "The new passwords do not match.";

        if (empty($errors)) {
            $u = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
            $u->execute([password_hash($new, PASSWORD_DEFAULT), $uid]);
            session_regenerate_id(true);
            $msg = "Password changed.";
        }
    }
}

// ---------- Booking summary ----------
$st = $pdo->prepare(
    "SELECT COUNT(*) AS total,
            COALESCE(SUM(res_date >= CURDATE() AND status <> 'cancelled'), 0) AS upcoming
     FROM reservations WHERE user_id = ?"
);
$st->execute([$uid]);
$stats = $st->fetch(PDO::FETCH_ASSOC);

$initials = strtoupper(substr($user["first_name"], 0, 1) . substr($user["last_name"], 0, 1));

page_top("My Profile");
?>
<div class="profile-head">
    <div class="avatar"><?= e($initials) ?></div>
    <div>
        <h2><?= e($user["first_name"] . " " . $user["last_name"]) ?></h2>
        <p class="profile-meta">
            @<?= e($user["username"]) ?>
            <?php if ($user["role"] === "admin"): ?><span class="badge badge-confirmed">Admin</span><?php endif; ?>
        </p>
    </div>
</div>

<?php if ($msg): ?><div class="success"><?= e($msg) ?></div><?php endif; ?>
<?php if ($errors): ?>
    <div class="error"><?php foreach ($errors as $err): ?><div><?= e($err) ?></div><?php endforeach; ?></div>
<?php endif; ?>

<div class="stats">
    <div class="card stat"><strong><?= (int)$stats["total"] ?></strong>Total bookings</div>
    <div class="card stat"><strong><?= (int)$stats["upcoming"] ?></strong>Upcoming bookings</div>
    <div class="card stat"><strong><?= e(date("j M Y", strtotime($user["created_at"]))) ?></strong>Member since</div>
</div>

<form action="" method="POST" class="card">
    <h3 style="margin-top:0">Personal details</h3>
    <input type="hidden" name="action" value="details">

    <label for="username">Username</label>
    <input type="text" id="username" value="<?= e($user["username"]) ?>" disabled>

    <div class="row3" style="grid-template-columns:1fr 1fr">
        <div class="field">
            <label for="fname">First name</label>
            <input type="text" name="fname" id="fname" value="<?= e($form["first_name"]) ?>" required>
        </div>
        <div class="field">
            <label for="lname">Last name</label>
            <input type="text" name="lname" id="lname" value="<?= e($form["last_name"]) ?>" required>
        </div>
    </div>

    <label for="email">Email</label>
    <input type="email" name="email" id="email" value="<?= e($form["email"]) ?>" required>

    <label for="phone">Phone number</label>
    <input type="tel" name="phone" id="phone" value="<?= e($form["phone"]) ?>" required>

    <div class="actions"><button type="submit">Save changes</button></div>
</form>

<form action="" method="POST" class="card">
    <h3 style="margin-top:0">Change password</h3>
    <input type="hidden" name="action" value="password">

    <label for="current_password">Current password</label>
    <input type="password" name="current_password" id="current_password" required>

    <label for="new_password">New password</label>
    <input type="password" name="new_password" id="new_password" placeholder="At least 8 characters" required>

    <label for="confirm_password">Confirm new password</label>
    <input type="password" name="confirm_password" id="confirm_password" required>

    <div class="actions"><button type="submit">Change password</button></div>
</form>
<?php page_bottom(); ?>