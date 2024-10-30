=== IP Guard ===

Contributors: Dynahsty

Tags: security, block-IP, login-protect, Auth-security, IP-secure

Donate link: https://flutterwave.com/donate/dmoszdenwggm

Requires at least: 5.0

Tested up to: 6.4.3

Requires PHP: 7.4

Stable tag: 1.23.2

License: GPLv2 or later

License URI: http://www.gnu.org/licenses/gpl-2.0.html



**IPGuard** is a robust security plugin that empowers administrators to safeguard user accounts by implementing IP address-based lockdowns.



== Description ==

**IP Guard** is a robust plugin that provides functionality to lock WordPress registered user accounts based on the IP address limit set by the administrator. 



The plugin includes many features with a simple interface and uses the *wp_mail* function to send emails for notifications on locked and unlocked activities. This approach helps enhance security by monitoring and restricting access based on IP addresses, providing an additional layer of protection for user accounts.



For example, if the administrator set allowed IP address for registered users should be 2, once a user reached the limit which is 2, the account gets automatically locked and display a error message on the login page. The admin can decide to manually unlock the account or the user can wait 7 days for an automatic unlock. 

Tested with:-
Login/Signup Popup (Inline Form + Woocommerce) plugin..


**Features of IP Guard**

1. Locking mechanism that automatically locks accounts based on set IP address

2. Automatically sends mail notifications for locked and unlocked activities 

3. A admin locked accounts page which displays locked accounts, username and a button for manual unlocking. Note - automatic unlock of user accounts is set to 7 days

4. A admin logs page which displays the detected IP address, username and country 

5. A admin settings page for configuration of the plugin such as setting the maximum IP address allowed, body text for locked and unlocked emails, custom mail notification logo and copyright text

6. A user statistics page which displays total number of registered users, administrators and locked accounts

7. Similar IP in pattern, structure or share the same first and second octets wont get locked



== Installation ==

1. Upload \"IPGuard plugin\" to the \"/wp-content/plugins/\" directory or uploading the file to your web server. 

2. Activate the plugin through the \"Plugins\" menu in WordPress admin dashboard. 

3. Enjoy the full functionality of IPGuard

4. Tested with:- Login/Signup Popup (Inline Form + Woocommerce) plugin..




== Attributions ==


Thanks to the provider for the following services and REST APIs for free.

https://ipinfo.io/ (IPv4, IPv6 / free)


== Contributors ==


IPGuard is an open-source project and welcomes all contributors from code to design, and implement new features. For more info <a href="https://developer.wordpress.org/block-editor/contributors/">Contributor's Handbook</a> for all the details on how you can help.



== Frequently Asked Questions ==

How does the IPGuard work?



IPGuard is a robust security plugin that empowers administrators to safeguard user accounts by implementing IP address-based lockdowns, enhancing your website\'s overall security. It’s a perfect plugin for admin who doesn’t want to allow users sharing as the locking mechanism automatically lock accounts based on allowed IP address per account. 



Does it notify users?



Yes, the plugin sends notifications to the user based on locked and unlocked activities. It uses the wp_mail function, so make sure you\'ve set your SMTP correctly before using our plugin. 



Have issues/questions or want to contribute?



You can post in the support forum or consider reaching me at holakhunle@gmail.com



Can I customize ban notifications and other things?



The plugin provides a settings page whereby you can set the maximum IP address allowed, locked email body text, and unlocked email body text. It also includes a submenu page that displays IP logs detected such as the username, ip addresses, and country.



== Screenshots ==

1. https://i.postimg.cc/L6Fj14xC/Screenshot-1.png

2. https://i.postimg.cc/SRWD0s4x/Screenshot-2.png

3. https://i.postimg.cc/yNGZY7JT/Screenshot-2.png



== Changelog ==

= 1.23.2 =

* Minor bug fixes


= 1.23.1 =

* Similar IP in pattern, structure or share the same first and second octets wont get locked

* Added a warning notification mail if users are reaching the threshold


= 1.23 =

* Fixed locking mechanism errors for similar ip address

* Improved UI Design for Locked account, Settings and Logs page


= 1.22 =

* Added logs page for displaying detected IP logs statistics

* Added User Statistics to display total number of users, admins and locked accounts 



= 1.0 =

* Initial release.



== Upgrade Notice ==


= 1.23.2 =

* Minor bug fixes


= 1.23.1 =

* Dynamic IP Addresses are considered and don't get locked if they are under the same subnet

* Added a warning notification mail if users are reaching the threshold



= 1.23 =

This version fixes some bugs with the plugin such as locking similar address and also UI has been redesigned. 



= 1.22 =

This version adds new features such as Logs page for displaying detected IP address, username and country. Added Users Statistics to display total number of users registered on the website including admins and locked accounts 



= 1.0=

Initial release of the plugin

