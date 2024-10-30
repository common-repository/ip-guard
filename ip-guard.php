<?php
/*
Plugin Name: IPGuard
Description: A robust security plugin that empowers administrators to safeguard user accounts by implementing IP address-based lockdowns.
Version: 1.23.2
Author: <a href="https://wa.link/kemj38">Dynasty</a>
Contributors: Dynahsty
Tags: security, block-IP, login-protect, Auth-security, IP-secure
Donate link: https://flutterwave.com/donate/dmoszdenwggm
Requires at least: 5.0
Tested up to: 6.4.3
Requires PHP: 7.4
Stable tag: 1.23.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
*/

$max_ip_addresses = get_option('ip_guard_max_ip_addresses', 2);

define('IP_GUARD_MAX_IP_ADDRESSES', $max_ip_addresses);
define('IP_GUARD_MAX_LOCK_DURATION', 7 * 24 * 60 * 60);

add_filter('authenticate', 'ip_guard_authenticate', 20, 3);

function ip_guard_authenticate($user, $username, $password) {
    if ($user instanceof WP_User && !in_array('administrator', (array) $user->roles)) {
        $stored_ips = get_user_meta($user->ID, '_stored_ips', true);
        if (!$stored_ips) {
            $stored_ips = array();
        }

        $client_ip = isset($_SERVER['REMOTE_ADDR']) ? filter_var($_SERVER['REMOTE_ADDR'], FILTER_SANITIZE_STRING) : '';

        if ($client_ip && filter_var($client_ip, FILTER_VALIDATE_IP)) {
            $first_octet = explode('.', $client_ip)[0];
            $similar_ip_exists = false;
            foreach ($stored_ips as $stored_ip) {
                if (strpos($stored_ip, $first_octet . '.') === 0) {
                    $similar_ip_exists = true;
                    break;
                }
            }

            if (!$similar_ip_exists) {
                $stored_ips[] = $client_ip;
                update_user_meta($user->ID, '_stored_ips', $stored_ips);
            }

            $max_ip_addresses = intval(get_option('ip_guard_max_ip_addresses', 2));

            $all_similar = ip_addresses_similar($stored_ips);
            if (count($stored_ips) == $max_ip_addresses - 1) {
                ip_guard_send_warning_email($user->ID);
            }

            if (!$all_similar && count($stored_ips) >= $max_ip_addresses) {
                ip_guard_lock_user($user->ID);
                return new WP_Error('account_locked', __('Account locked due to unusual activity. Contact our support team.', 'ip-guard'));
            }
        }
    }

    return $user;
}


function ip_addresses_similar($ip_addresses) {
    $ip_groups = [];
    foreach ($ip_addresses as $ip) {
        $first_octet = explode('.', $ip)[0];
        $ip_groups[$first_octet][] = $ip;
    }
    
    foreach ($ip_groups as $group) {
        if (!all_ip_addresses_similar_in_group($group)) {
            return false;
        }
    }

    return true;
}

function all_ip_addresses_similar_in_group($ip_group) {
    $first_ip_octets = explode('.', reset($ip_group));

    foreach ($ip_group as $ip) {
        $current_ip_octets = explode('.', $ip);

        if (count($first_ip_octets) !== count($current_ip_octets)) {
            return false;
        }

        for ($i = 1; $i < count($first_ip_octets); $i++) {
            if ($first_ip_octets[$i] !== $current_ip_octets[$i]) {
                return false;
            }
        }
    }

    return true;
}

function construct_email_body($logo_url, $email_body) {
    $logo_url = esc_url($logo_url);

    $email_body = $email_body ? wpautop(wp_kses_post($email_body)) : 'Default email body';

    $body = '<div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px; font-family: \'Helvetica Neue\', Helvetica, Arial, sans-serif;">';
    $body .= '<img src="' . $logo_url . '" alt="Logo" style="max-width: 150px; margin-bottom: 20px; display: block; margin: 0 auto;">';
    $body .= '<div style="background-color: #ffffff; padding: 20px; border-radius: 5px;">';
    $body .= '<div style="color: #333; font-size: 16px; line-height: 1.6; text-align: left;">' . $email_body . '</div>';
    $body .= '</div>';
    $body .= '<div style="text-align: center; margin-top: 20px; color: #888; font-size: 12px;">';
    $body .= esc_html(get_option('ip_guard_copyright_text', ''));
    $body .= '</div>';
    $body .= '</div>';
    return $body;
}

function ip_guard_send_warning_email($user_id) {
    $user_info = get_userdata($user_id);
    
    if (!$user_info) {
        return;
    }
    
    $to = $user_info->user_email;

    if (!is_email($to)) {
        return;
    }

    $subject = __('Warning: You are reaching the threshold limit', 'ip-guard');
    $warning_email_body = get_option('ip_guard_warning_email_body', '');
    $logo_url = get_option('ip_guard_logo_url', '');

    $message = construct_email_body($logo_url, $warning_email_body);

    $headers[] = 'Content-Type: text/html; charset=UTF-8';
    wp_mail($to, $subject, $message, $headers);
}

function ip_guard_manually_lock_user($user_id) {
    update_user_meta($user_id, '_ip_guard_account_manually_locked', true);
    $user_info = get_userdata($user_id);
    $to = $user_info->user_email;
    $subject = __('Your account has been locked', 'ip-guard');
    $lock_email_body = get_option('ip_guard_lock_email_body', '');
    $logo_url = get_option('ip_guard_logo_url', '');
    
    $message = construct_email_body($logo_url, $lock_email_body);
    
    $headers[] = 'Content-Type: text/html; charset=UTF-8';
    wp_mail($to, $subject, $message, $headers);
}

function ip_guard_manually_unlock_user($user_id) {
    delete_user_meta($user_id, '_account_locked');
    delete_user_meta($user_id, '_lock_time');
    delete_user_meta($user_id, '_stored_ips');
    delete_user_meta($user_id, '_ip_guard_account_manually_locked');

    $user_info = get_userdata($user_id);
    $to = $user_info->user_email;
    $subject = __('Your account has been unlocked', 'ip-guard');
    $unlock_email_body = get_option('ip_guard_unlock_email_body', '');
    $logo_url = get_option('ip_guard_logo_url', '');
    
    $message = construct_email_body($logo_url, $unlock_email_body);
    
    $headers[] = 'Content-Type: text/html; charset=UTF-8';
    wp_mail($to, $subject, $message, $headers);
}

function ip_guard_lock_user($user_id) {
    if (get_user_meta($user_id, '_account_locked', true)) {
        return;
    }

    update_user_meta($user_id, '_account_locked', true);
    update_user_meta($user_id, '_lock_time', time());
    
    $user_info = get_userdata($user_id);
    $to = $user_info->user_email;
    $subject = __('Your account has been locked', 'ip-guard');
    $lock_email_body = get_option('ip_guard_lock_email_body', '');
    $logo_url = get_option('ip_guard_logo_url', '');
    
    $message = construct_email_body($logo_url, $lock_email_body);
    
    $headers[] = 'Content-Type: text/html; charset=UTF-8';
    wp_mail($to, $subject, $message, $headers);
}

function ip_guard_unlock_user($user_id) {
    if (!get_user_meta($user_id, '_account_locked', true)) {
        return;
    }

    $lock_time = get_user_meta($user_id, '_lock_time', true);
    $lock_duration = 7 * 24 * 60 * 60;

    if (time() - $lock_time >= $lock_duration) {
        delete_user_meta($user_id, '_account_locked');
        delete_user_meta($user_id, '_lock_time');
        delete_user_meta($user_id, '_stored_ips');

        $user_info = get_userdata($user_id);
        $to = $user_info->user_email;
        $subject = __('Your account has been automatically unlocked', 'ip-guard');
        $unlock_email_body = get_option('ip_guard_unlock_email_body', '');
        $logo_url = get_option('ip_guard_logo_url', '');
        
        $message = construct_email_body($logo_url, $unlock_email_body);
        
        $headers[] = 'Content-Type: text/html; charset=UTF-8';
        wp_mail($to, $subject, $message, $headers);
        return;
    }

    $unlock_already_performed = get_transient('unlock_user_' . $user_id);
    if ($unlock_already_performed) {
        return;
    }

    if (!empty($_GET['action']) && $_GET['action'] === 'unlock_account') {
        delete_user_meta($user_id, '_account_locked');
        delete_user_meta($user_id, '_lock_time');
        delete_user_meta($user_id, '_stored_ips');

        $user_info = get_userdata($user_id);
        $to = $user_info->user_email;
        $subject = __('Your account has been manually unlocked', 'ip-guard');
        $unlock_email_body = get_option('ip_guard_unlock_email_body', '');
        $logo_url = get_option('ip_guard_logo_url', '');
        
        $message = construct_email_body($logo_url, $unlock_email_body);
        
        $headers[] = 'Content-Type: text/html; charset=UTF-8';
        wp_mail($to, $subject, $message, $headers);

        set_transient('unlock_user_' . $user_id, true, MINUTE_IN_SECONDS);
    }
}


add_action('admin_menu', 'ip_guard_admin_menu');

function ip_guard_admin_menu() {
    add_menu_page(
        __('Locked Accounts', 'ip-guard'),
        __('Locked Accounts', 'ip-guard'),
        'manage_options',
        'ip_guard_admin_page',
        'ip_guard_admin_page_content',
        'dashicons-lock'
    );

    add_submenu_page(
        'ip_guard_admin_page',
        __('IP Logs', 'ip-guard'),
        __('IP Logs', 'ip-guard'),
        'manage_options',
        'ip_guard_logs_page',
        'ip_guard_logs_page_content'
    );
    add_submenu_page(
        'ip_guard_admin_page',
        __('Settings', 'ip-guard'),
        __('Settings', 'ip-guard'),
        'manage_options',
        'ip_guard_settings_page',
        'ip_guard_settings_page_content'
    );
    add_submenu_page(
        'ip_guard_admin_page',
        __('Users', 'ip-guard'),
        __('Users', 'ip-guard'),
        'manage_options',
        'ip_guard_dashboard',
        'ip_guard_dashboard_content'
    );
    add_submenu_page(
        'ip_guard_admin_page',
        __('Donate', 'ip-guard'),
        __('Donate', 'ip-guard'),
        'manage_options',
        'ip_guard_donation_page',
        'ip_guard_donation_page_content'
    );
}

function ip_guard_dashboard_content() {
    ?>
    <div class="wrap">
        <div class="dashboard-container">
            <h1 class="dashboard-title"><?php esc_html_e('Users', 'ip-guard'); ?></h1>

            <div class="card-container">
                <div class="card">
                    <h2><?php esc_html_e('Total Users', 'ip-guard'); ?></h2>
                    <p class="user-count"><?php echo esc_html(ip_guard_get_total_users_count()); ?></p>
                </div>

                <div class="card">
                    <h2><?php esc_html_e('Administrators', 'ip-guard'); ?></h2>
                    <p class="admin-count"><?php echo esc_html(ip_guard_get_administrators_count()); ?></p>
                </div>

                <div class="card">
                    <h2><?php esc_html_e('Locked Accounts', 'ip-guard'); ?></h2>
                    <p class="locked-count"><?php echo esc_html(ip_guard_get_locked_accounts_count()); ?></p>
                </div>
            </div>
        </div>
    </div>

    <style>
        .dashboard-container {
            padding: 20px;
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .dashboard-title {
            font-family: 'Arial', sans-serif;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .card-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            justify-content: space-between;
        }

        .card {
            background-color: #f5f5f5;
            border: 2px solid #3498db;
            padding: 30px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            box-sizing: border-box;
            max-width: 100%;
            margin-top: 20px;
            margin-left: auto;
            margin-right: auto;
        }

        .user-count,
        .admin-count,
        .locked-count {
            background-color: #007bff;
            color: #fff;
            padding: 10px;
            border-radius: 5px;
            display: inline-block;
        }

        .admin-count {
            background-color: #dc3545;
        }

        .locked-count {
            background-color: #28a745;
        }
    </style>
    <?php
}

function ip_guard_get_total_users_count() {
    $user_count = count_users();
    return $user_count['total_users'];
}

function ip_guard_get_administrators_count() {
    $admin_count = count_users();
    return $admin_count['avail_roles']['administrator'];
}

function ip_guard_get_locked_accounts_count() {
    $args = array(
        'meta_key'     => '_account_locked',
        'meta_value'   => 1,
        'meta_compare' => '=',
    );

    $query = new WP_User_Query($args);
    $locked_users = $query->get_results();
    return count($locked_users);
}

function ip_guard_admin_page_content() {
    ?>
    <div class="wrap">
        <div class="card">
            <h1 class="locked-heading"><?php esc_html_e('Locked Accounts', 'ip-guard'); ?></h1>

            <?php
           if (isset($_GET['action']) && $_GET['action'] === 'unlock_account' && isset($_GET['user_id'])) {
                $user_id = absint($_GET['user_id']);
                ip_guard_manually_unlock_user($user_id);
                ?>
                <div id="message" class="updated notice is-dismissible">
                    <p><?php esc_html_e('User account has been successfully unlocked. An email notification has been sent to the user.', 'ip-guard'); ?></p>
                </div>
                <?php
            }
            ?>

            <div class="table-container">
                <table class="ip-guard-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Username', 'ip-guard'); ?></th>
                            <th><?php esc_html_e('Locked Type', 'ip-guard'); ?></th>
                            <th><?php esc_html_e('Actions', 'ip-guard'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $manually_locked_users = get_users(array(
                            'meta_key'     => '_ip_guard_account_manually_locked',
                            'meta_value'   => 1,
                            'meta_compare' => '=',
                        ));

                        foreach ($manually_locked_users as $user) {
                            ?>
                            <tr>
                                <td><?php echo esc_html($user->user_login); ?></td>
                                <td><?php esc_html_e('Manual', 'ip-guard'); ?></td>
                                <td>
                                    <a class="button button-primary unlock-button" href="<?php echo esc_url(add_query_arg(array('action' => 'unlock_account', 'user_id' => $user->ID), admin_url('admin.php?page=ip_guard_admin_page'))); ?>">
                                        <?php esc_html_e('Unlock', 'ip-guard'); ?>
                                    </a>
                                </td>
                            </tr>
                            <?php
                        }
                        $automatically_locked_users = get_users(array(
                            'meta_key'     => '_account_locked',
                            'meta_value'   => 1,
                            'meta_compare' => '=',
                        ));

                        foreach ($automatically_locked_users as $user) {
                            ?>
                            <tr>
                                <td><?php echo esc_html($user->user_login); ?></td>
                                <td><?php esc_html_e('Exceeded Limit', 'ip-guard'); ?></td>
                                <td>
                                    <a class="button unlock-button" href="<?php echo esc_url(add_query_arg(array('action' => 'unlock_account', 'user_id' => $user->ID), admin_url('admin.php?page=ip_guard_admin_page'))); ?>">
                                        <?php esc_html_e('Unlock User', 'ip-guard'); ?>
                                    </a>
                                </td>
                            </tr>
                            <?php
                        }

                        if (empty($manually_locked_users) && empty($automatically_locked_users)) {
                            ?>
                            <tr>
                                <td colspan="3"><?php esc_html_e('No detected accounts found.', 'ip-guard'); ?></td>
                            </tr>
                            <?php
                        }
                        ?>
                    </tbody>
                </table>
            </div>
        </div>
        <div class="about-plugin-card">
            <h2><?php esc_html_e('Locked Account Tab', 'ip-guard'); ?></h2>
            <p><?php esc_html_e('This page displays a list of locked users with a button for manual unlocking. Automatic unlock is set at 7 days', 'ip-guard'); ?></p>
        </div>
    </div>

    <style>
        .card-container {
            display: flex;
            gap: 20px;
            justify-content: space-between;
            flex-wrap: wrap;
        }

        .card {
            background-color: #f5f5f5;
            border: 2px solid #3498db;
            padding: 30px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            box-sizing: border-box;
            max-width: 100%;
            margin-top: 20px;
            margin-left: auto;
            margin-right: auto;
            overflow-x: auto;
        }
        
        .locked-heading {
        font-family: "Arial", sans-serif; 
        font-weight: bold;
    }

        .table-container {
            overflow-x: auto;
        }

        .ip-guard-table {
            width: 100%;
            border-collapse: collapse;
        }

        .ip-guard-table th,
        .ip-guard-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .ip-guard-table th {
            background-color: #3498db;
            color: #fff;
            font-weight: bold;
        }

       .unlock-button {
    background-color: #0073aa !important;
    color: #fff !important;
    padding: 8px 16px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    text-decoration: none;
    border-radius: 4px;
}

.about-plugin-card {
    background-color: #f5f5f5;
    border: 2px solid #3498db;
    padding: 30px;
    border-radius: 20px; 
    box-sizing: border-box;
    max-width: 70%;
    margin-top: 30px;
    overflow-x: auto;
    margin-left: auto;
    margin-right: auto;
}

.about-plugin-card h2,
.about-plugin-card p {
    margin: 0;
}

    </style>
    <?php
}

function ip_guard_settings_page_content() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'ip-guard'));
    }

    if (isset($_POST['submit']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])), 'ip_guard_settings_nonce')) {
        $max_ip_addresses = isset($_POST['max_ip_addresses']) ? absint(sanitize_text_field($_POST['max_ip_addresses'])) : 0;
        update_option('ip_guard_max_ip_addresses', $max_ip_addresses);

        $lock_email_body = isset($_POST['lock_email_body']) ? wp_kses_post(wp_unslash($_POST['lock_email_body'])) : '';
        update_option('ip_guard_lock_email_body', $lock_email_body);

        $unlock_email_body = isset($_POST['unlock_email_body']) ? wp_kses_post(wp_unslash($_POST['unlock_email_body'])) : '';
        update_option('ip_guard_unlock_email_body', $unlock_email_body);
        
        $warning_email_body = isset($_POST['warning_email_body']) ? wp_kses_post(wp_unslash($_POST['warning_email_body'])) : '';
        update_option('ip_guard_warning_email_body', $warning_email_body); // New field

        $logo_url = isset($_POST['logo_url']) ? esc_url_raw($_POST['logo_url']) : '';
        update_option('ip_guard_logo_url', $logo_url);
        
        $copyright_text = isset($_POST['copyright_text']) ? sanitize_text_field($_POST['copyright_text']) : '';
        update_option('ip_guard_copyright_text', $copyright_text);

        echo '<div id="message" class="updated notice is-dismissible"><p>'
            . esc_html__('Settings successfully saved.', 'ip-guard') . '</p></div>';
    }

    $max_ip_addresses = get_option('ip_guard_max_ip_addresses', IP_GUARD_MAX_IP_ADDRESSES);
    $lock_email_body = get_option('ip_guard_lock_email_body', '');
    $unlock_email_body = get_option('ip_guard_unlock_email_body', '');
    $warning_email_body = get_option('ip_guard_warning_email_body', ''); // New field
    $logo_url = get_option('ip_guard_logo_url', '');
    $copyright_text = get_option('ip_guard_copyright_text', '');

    ?>

    <div class="wrap">
        <div class="card">
            <h1><?php esc_html_e('Settings', 'ip-guard'); ?></h1>

            <form method="post" action="">
                <?php wp_nonce_field('ip_guard_settings_nonce'); ?>

                <div class="form-group" style="max-width: 400px; margin: 0 auto;">
                    <label for="max_ip_addresses" style="display: inline-block; margin-bottom: 5px;"><?php esc_html_e('Maximum IP Addresses Allowed:', 'ip-guard'); ?></label>
                    <input type="number" id="max_ip_addresses" name="max_ip_addresses" value="<?php echo esc_attr($max_ip_addresses); ?>" min="1" required style="display: inline-block; width: calc(100% - 10px); box-sizing: border-box; margin-bottom: 15px;">
                    <p class="description" style="text-align: left;"><?php esc_html_e('Enter the maximum number of allowed IP addresses per account.', 'ip-guard'); ?></p>
                </div>

                <div class="form-group">
                    <label for="lock_email_body"><?php esc_html_e('Locked Email Body:', 'ip-guard'); ?></label>
                    <?php wp_editor($lock_email_body, 'lock_email_body', array('textarea_name' => 'lock_email_body', 'textarea_rows' => 4)); ?>
                    <p class="description"><?php esc_html_e('Enter the body text for the email sent when an account is locked.', 'ip-guard'); ?></p>
                </div>

                <div class="form-group">
                    <label for="unlock_email_body"><?php esc_html_e('Unlocked Email Body:', 'ip-guard'); ?></label>
                    <?php wp_editor($unlock_email_body, 'unlock_email_body', array('textarea_name' => 'unlock_email_body', 'textarea_rows' => 4)); ?>
                    <p class="description"><?php esc_html_e('Enter the body text for the email sent when an account is unlocked.', 'ip-guard'); ?></p>
                </div>
                
                 <div class="form-group">
                    <label for="warning_email_body"><?php esc_html_e('Warning Email Body:', 'ip-guard'); ?></label>
                    <?php wp_editor($warning_email_body, 'warning_email_body', array('textarea_name' => 'warning_email_body', 'textarea_rows' => 4)); ?>
                    <p class="description"><?php esc_html_e('Enter the body text for the warning email sent when the user is close to reaching the IP threshold limit.', 'ip-guard'); ?></p>
                </div>
                
                <div class="form-group">
                    <label for="logo_url"><?php esc_html_e('Logo URL:', 'ip-guard'); ?></label>
                    <input type="text" id="logo_url" name="logo_url" value="<?php echo esc_attr($logo_url); ?>" style="width: 80%;" placeholder="<?php esc_attr_e('Enter the URL to your logo image', 'ip-guard'); ?>">
                </div>
                
                <div class="form-group">
                    <label for="copyright_text"><?php esc_html_e('Copyright Text:', 'ip-guard'); ?></label>
                    <input type="text" id="copyright_text" name="copyright_text" value="<?php echo esc_attr($copyright_text); ?>" style="width: 50%;">
                </div>

                <p><input type="submit" name="submit" class="button-primary" style="background-color:#0073aa;" value="<?php esc_attr_e('Save Settings', 'ip-guard'); ?>"></p>
            </form>
        </div>
    <div class="card instructions-container">
        <h2><?php esc_html_e('Instructions', 'ip-guard'); ?></h2>
        <p><?php esc_html_e('Please configure email settings on your website first by setting up your SMTP Host.', 'ip-guard'); ?></p>
        <p><?php esc_html_e('Fill in the body text field with what you want being sent for either locked emails or unlocked.', 'ip-guard'); ?></p>
    </div>
</div>
    <style>
        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
        }

        input[type="number"],
        textarea {
            width: 100%;
        }

        .card {
            background-color: #f5f5f5;
            border: 2px solid #3498db;
            padding: 30px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            box-sizing: border-box;
            max-width: 100%;
            margin-top: 20px;
            margin-left: auto;
            margin-right: auto;
            text-align: center; 
        }

        .instructions-container {
            background-color: #f5f5f5;
            border: 2px solid #3498db;
            padding: 30px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
            border-radius: 20px;
            box-sizing: border-box;
            max-width: 100%;
            width: 20%;
            box-sizing: border-box;
        }

        .button-primary {
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
        }
    </style>
    <?php
}

function ip_guard_logs_page_content() {
    ?>
    <div class="wrap">
        <div class="card">
            <h1 class="logs-heading"><?php esc_html_e('IP Logs', 'ip-guard'); ?></h1>

            <div class="table-responsive">
                <table class="table ip-guard-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Username', 'ip-guard'); ?></th>
                            <th><?php esc_html_e('IP Addresses', 'ip-guard'); ?></th>
                            <th><?php esc_html_e('Country', 'ip-guard'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $locked_users_with_all_ips = get_users(array(
                            'meta_key'     => '_account_locked',
                            'meta_value'   => 1,
                            'meta_compare' => '=',
                        ));

                        foreach ($locked_users_with_all_ips as $user) {
                            ?>
                            <tr>
                                <td><?php echo esc_html($user->user_login); ?></td>
                                <td>
                                    <?php
                                    $ip_addresses = get_user_meta($user->ID, '_stored_ips', true);
                                    echo esc_html(implode(', ', $ip_addresses));
                                    ?>
                                </td>
                                <td>
                                    <?php
                                    foreach ($ip_addresses as $ip) {
                                        $response = wp_remote_get("http://ipinfo.io/{$ip}/json");
                                        if (!is_wp_error($response)) {
                                            $ip_info = json_decode(wp_remote_retrieve_body($response));
                                            if ($ip_info && isset($ip_info->country)) {
                                                echo esc_html($ip_info->country) . ', ';
                                            }
                                        }
                                    }
                                    ?>
                                </td>
                            </tr>
                            <?php
                        }

                        if (empty($locked_users_with_all_ips)) {
                            ?>
                            <tr>
                                <td colspan="3"><?php esc_html_e('No logs found.', 'ip-guard'); ?></td>
                            </tr>
                            <?php
                        }
                        ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="instructions-container">
            <h2><?php esc_html_e('IP Logs Tab', 'ip-guard'); ?></h2>
            <p><?php esc_html_e('This page displays the total number of IP Addresses connected to the locked account.', 'ip-guard'); ?></p>
        </div>
    </div>

    <style>
        .card {
            background-color: #f5f5f5;
            border: 2px solid #3498db;
            padding: 30px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            box-sizing: border-box;
            max-width: 100%;
            margin-top: 20px;
            margin-left: auto;
            margin-right: auto;
            overflow-x: auto;
        }

        .logs-heading {
            font-family: Arial, sans-serif;
            font-weight: bold;
        }

        .ip-guard-table {
            width: 100%;
        }

        .ip-guard-table th,
        .ip-guard-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .ip-guard-table th {
            background-color: #3498db;
            color: #fff;
            font-weight: bold;
        }

        .instructions-container {
            background-color: #f5f5f5;
            border: 2px solid #3498db;
            padding: 30px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
            border-radius: 20px;
            box-sizing: border-box;
            max-width: 100%;
            margin-top: 30px;
            overflow-x: auto;
            width: 70%;
            margin-left: auto;
            margin-right: auto;
        }

        .instructions-container h2,
        .instructions-container p {
            margin: 0;
        }
    </style>
    <?php
}

function ip_guard_donation_page_content() {
    ?>
    <div class="wrap">
        <div class="card-container">
            <div class="card">
                <h1 class="donation-heading">
                    <?php esc_html_e('Donation', 'ip-guard'); ?>
                </h1>
                <div class="donation-container">
                    <p>
                        <?php esc_html_e('Support our project by making a donation. We appreciate your contribution!', 'ip-guard'); ?>
                    </p>
                    <form action="https://flutterwave.com/donate/dmoszdenwggm" method="post" target="_blank">
                        <button type="submit" class="button-primary">
                            <?php esc_html_e('Make a Donation', 'ip-guard'); ?>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    <style>
        .card-container {
            display: flex;
            gap: 20px;
        }

        .card {
            background-color: #f5f5f5;
            border: 2px solid #3498db; 
            padding: 30px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            box-sizing: border-box;
            max-width: 100%;
            margin-top: 20px;
            margin-left: auto;
            margin-right: auto;
        }

        .donation-heading {
            font-family: 'Arial', sans-serif;
            font-weight: bold;
        }

        .donation-container {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
    </style>

    <?php
}
function ip_guard_settings_link($links) {
    $settings_link = '<a href="' . esc_url(admin_url('admin.php?page=ip_guard_settings_page')) . '">' . esc_html__('Settings', 'ip-guard') . '</a>';
    array_unshift($links, $settings_link);
    return $links;
}
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'ip_guard_settings_link');