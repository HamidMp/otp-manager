<?php

return [

    'message_provider'=>'',

    'user_model'=>App\Models\User::class,

    'token_field_source'=> 'header',//bearer, cookie, session, header
    'token_field_name'=>'otp_token',

    'user_contact'=> 'mobile',//will use for duplicate check and limitations and sending message

    'user_token'=> 'otp_token',//will store in otp-model and user-model and cookie and will use for limitations

    'delay_per_request'=>60,//seconds
    'time_to_answer'=>120,//seconds
    'max_wrong_try'=>0,
    'max_failed_ip_day'=>5,//maximum number of failed try in a day per ip
    'max_failed_contact_day'=>5,//maximum number of failed try in a day per contact
    'check_ip'=> false,//will use for duplicate check and limitations

    'verification_lifetime'=> 60*24,//minutes - zero for no expiration

    'password_length'=> 5,
    'encode_password'=> false,
    'only_digit_password'=> true,
    'single_device'=> false,

    'key'=> 'OTPManager',

    'guard'=> 'web',

];
