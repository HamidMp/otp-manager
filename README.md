## OTP Manager (Laravel library)

**OTP Manager** is a Laravel OTP library.  
Verification user by One Time Password via SMS or email or anything else.
You can choose various type of authentication method like cookie or request-header.

#### some features:
You can create **OTP link** and sending through **email** or create **OTP PIN code** and sending through **SMS** or notification etc.
You can choose between __cookie__ or __request-header__ (localstorage or fix variable) in client-side.  
_Note: In this tools you can using verification even without user._

## One Time Password
A one-time password (OTP), also known as one-time PIN or dynamic password, is a password that is valid for only one login session or transaction, on a computer system or other digital device.


## Installation

1. Install requirements:
  
    _Require with [Composer](https://getcomposer.org/)_  
    ```shell script
    composer require hamidmp/otp-manager
    ```

1. Publishing files:  
    
   ```shell script
    artisan vendor:publish --tag otpmanager
    ```
    It will copy the migration files (two files) and config file and middleware file.
      
1. Change the config values to your prefer configs:
    1. you have to declare the password (PIN) sender class in config file which the password sender class must be implemented from `OTPMessageInterface`:
         
        ```php
        //config/otpmanage.php
        
        return [
        
        //...
        'message_provider'=>\App\Srvice\SMSProvider::class,
        //...
        
        ];
        ```
        
    1. you have to declare the authenticable class for `user_model`:
          
        ```php
        //config/otpmanage.php
        
        return [
        
        //...
        'user_model'=>App\Models\User::class,
        //...
        
        ];
        ```
        
1. Config the database connection (you have done before)
1. Cache the configs:

    ```shell script
    artisan config:cache
    ```
   
1. Migrate the migrations

    ```shell script
    artisan migrate
    ```
    It will create new taable 'otpassword' for storing OTP PINs and adding two fields in `user_model` table (step 3.2) for user contact value (like mobile) and OTP-token.


## Usage

* Using middleware for checking user authentication

    ```php
    //routes/web.ph
    
    
    Route::middleware([\App\Http\Middleware\OTPManagerMiddleware::class])
        ->group(function () {
            //...
        });
    ```
  
* Taking user contact and generating new PIN and sending it

    ```php
    // App/Http/Controllers/SiteController
    
    OTPManager::generateAndSendNewOTP($request);
    ```
   
* Checking user PIN code

    ```php
    // App/Http/Controllers/SiteController
    
    $result = OTPManager::checkUserOTPAndVerification($request, $request->code);
    ```
  
* You can use the OTPManager without user and then after verification assign a user to that verified request

    ```php
    // App/Http/Controllers/SiteController
    
    $result = OTPManager::checkUserOTPAndVerification($request, $request->code);
    
    //just after verification
    if($result!==false){
        $user=User::find(1);
        OTPManager::assignUserTo($result,$user);
    }
    ```
 

## License

The DualSource library is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
