<?php


namespace HamidMp\OTPManager;


use App\Models\User;
use HamidMp\OTPManager\Models\OTPassword;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

class OTPManager
{

    /**
     * @var OTPMessageInterface $otpMessage
     */
    private $otpMessage;

    private $otpModelClass;

    //configs
    private $minimumDelayPerRequest;//seconds
    private $userIdentify;//array
    private $userContact;
    private $userToken;
    private $guard;
    private $shouldCheckIP;
    private $limitTimeToAnswer;//seconds
    private $maximumTryToAnswer;
    private $maximumFaildByIP;
    private $maximumFaildByContact;
    private $shouldEncodePassword;
    private $verificationLifeTime;//minutes
    private $tokenFieldSource;//cookie or session or request-header or request-parameter
    private $tokenFieldName;//field name of cookie or session or request-header or request-parameter
    private $singleDevice;//new verification will remove previous verifications
    private $fix_key;//for hash token
    private $passwordLength;
    private $onlyDigitPassword;
    private $user_model;
    private $messageProvider;

    //changed to tokenFieldName  <== private $cookie_field_name='otp_cookie';

    const OTP_STATUS_CREATED=0;
    const OTP_STATUS_WAIT=1;
    const OTP_STATUS_VERIFIED=2;
    const OTP_STATUS_ERROR=4;
    const OTP_STATUS_EXPIRED=5;

    const OTP_TOKEN_SOURCE_HEADER='header';
    const OTP_TOKEN_SOURCE_COOKIE='cookie';


    public function __construct(){

        //configs:  (sms , sms-code), (cookie-token, cookie-expire), user-mobile, user-token
        //configs:  (sms , sms-code), (session-token, logout), user-mobile, user-token
        //configs:  (email, link-code), (cookie-token, cookie-expire), user-email, user-token
        //configs:  (email, link-code), (session-token, logout), user-email, user-token

        $this->otpModelClass=config('otpmanager.model',OTPassword::class);

        $this->userIdentify=config('otpmanager.user_identify',['id','mobile']);
        $this->minimumDelayPerRequest=config('otpmanager.delay_per_request',60);//seconds
        $this->limitTimeToAnswer=config('otpmanager.time_to_answer',120);//seconds
        $this->maximumTryToAnswer=config('otpmanager.max_wrong_try',0);
        $this->maximumFaildByIP=config('otpmanager.max_failed_ip_day',5);//maximum number of failed try in a day per ip
        $this->maximumFaildByContact=config('otpmanager.max_failed_contact_day',5);//maximum number of failed try in a day per contact
        $this->userContact=config('otpmanager.user_contact','mobile');//will use for duplicate check and limitations and sending message
        $this->userToken=config('otpmanager.user_token','otp_token');//will store in otp-model and user-model and cookie and will use for limitations
        $this->shouldCheckIP=config('otpmanager.check_ip',false);//will use for duplicate check and limitations
        $this->passwordLength=config('otpmanager.password_length',5);
        $this->shouldEncodePassword=config('otpmanager.encode_password',false);
        $this->onlyDigitPassword=config('otpmanager.only_digit_password',true);
        $this->verificationLifeTime=config('otpmanager.verification_lifetime',60*24);//minutes - zero for no expiration
        $this->tokenFieldSource=config('otpmanager.token_field_source',self::OTP_TOKEN_SOURCE_COOKIE);
        $this->tokenFieldName=config('otpmanager.token_field_name','otp_token');
        $this->singleDevice=config('otpmanager.single_device',false);
        $this->fix_key=config('otpmanager.key','OTPManager');
        $this->guard=config('otpmanager.guard','web');
        $this->user_model=config('otpmanager.user_model',User::class);
        $this->messageProvider=config('otpmanager.message_provider');

        $this->otpMessage=app()->make($this->messageProvider);

    }

    private function findUserToken(Request $request){
        $userToken=null;

        switch ($this->tokenFieldSource){
            case self::OTP_TOKEN_SOURCE_HEADER:
                $userToken=data_get($request,$this->tokenFieldName,null);
                break;
            case self::OTP_TOKEN_SOURCE_COOKIE:
                $userToken=$request->cookie($this->tokenFieldName,null);
                break;
        }

        return $userToken;
    }

    private function findOTPasswordModelFromRequest(Request $request){
        $userToken=$this->findUserToken($request);
        if(empty($userToken))
            return false;
        $modelOTP=$this->findOTPasswordModelFromUserToken($userToken);
        return $modelOTP;
    }

    private function isExpired(OTPassword $modelOTP):bool{
        if(empty($this->verificationLifeTime))
            return false;
        $createDate=$modelOTP->created_at??'';
        $createDate=Carbon::parse($createDate);
        $diff=$createDate->diffInMinutes(Carbon::now());
        if($diff>$this->verificationLifeTime){
            return true;
        }

        return false;
    }

    private function doesOTPModelVerified(OTPassword $modelOTP){
        if(empty($modelOTP))
            return false;
        if ($modelOTP->hasVerified()) {
            if(!$this->isExpired($modelOTP)){
                return true;
            }
        }

        return false;
    }

    private function getVerifiedOTPModelFromRequest(Request $request){
        $modelOTP=$this->findOTPasswordModelFromRequest($request);
        if($modelOTP!==false){
            if($this->doesOTPModelVerified($modelOTP)===true){

                //check same ip
                if($this->shouldCheckIP){
                    if($modelOTP->user_ip!=$request->ip()) {
                        return false;
                    }
                }

                return $modelOTP;
            }
        }

        return false;
    }

    public static function checkAuthentication/*OrGetReadyUser*/(Request $request, $guard=''){
        $manager=new OTPManager();

        // check valid cookie (date, mobile, code)
        // if had cookie: check verified or not
        // if verified then return user
        // DELETED <== if not then create new token store new cookie

        $modelOTP=$manager->getVerifiedOTPModelFromRequest($request);
        if(empty($modelOTP)){
            return false;
        }
        $manager->doLoggedInUser($modelOTP, $guard);
        return $modelOTP->user;

        /*20210331

        $modelOTP=$manager->findOTPasswordModelFromRequest($request);

        if($modelOTP!==false){

            //check expire datetime
            if(!$manager->isExpired($modelOTP)) {
                if ($manager->doesOTPModelVerified($modelOTP)) {
                    $manager->doLoggedInUser($modelOTP, $guard);
                    return $modelOTP->user;
                } elseif ($modelOTP->isReady()) {
                    //is ready for OTP
                    return false;
                } else {
                    //error, failed, ...
                    //it means we have a bad usertoken and it should be changed
                }
            }
        }


        //DELETED <== if no cookie or not valid token then create new token store new cookie
        switch ($manager->tokenFieldSource){
            case 'cookie':
                Cookie::queue(Cookie::forget($manager->tokenFieldName));
                break;
        }
        //DELETED <== $manager->generateAndStoreNewUserToken($request);

        return false;
        */
    }

    public static function assignUserTo(OTPassword $otpModel, $user){
        if(empty($user))
            return false;
        $manager=new OTPManager();
        $otpModel->user()->associate($user);
        $manager->saveUserTokenInUser($user,$otpModel->user_token);
        $user->save();
        return $otpModel->save();
    }

    public static function logout(Request $request){

        //todo expire otpModel
        //todo remove cookie

        $manager=new OTPManager();
        $modelOTP=$manager->findOTPasswordModelFromRequest($request);

        if($modelOTP!==false){
            if ($modelOTP->hasVerified() || $modelOTP->isReady()) {
                $modelOTP->status=self::OTP_STATUS_EXPIRED;
                $modelOTP->save();
            }
        }

        Auth::guard($manager->guard)->logout();

        switch ($manager->tokenFieldSource){
            case self::OTP_TOKEN_SOURCE_COOKIE:
                Cookie::queue(Cookie::forget($manager->tokenFieldName));
                break;
        }

    }

    private function saveUserTokenInUser($user, $userToken){
        if(empty($user))
            return false;
        $user->{$this->userToken}=$userToken;
        return $user->save();
    }

    protected function doLoggedInUser(OTPassword $modelOTP, $guard=''){

        if(empty($guard))
            $guard=$this->guard;

        $modelOTP->load('user');
        $user=$modelOTP->user;
        if(empty($user))
            return false;
        Auth::guard($guard)->login($user);
        return $user;
    }

    private function generateAndStoreNewUserToken(Request $request){
        //generate new user-token
        //store user-token in cookie or table or session

        //token formula:  fix_key + ip + datetime + random
        $t=$this->fix_key.$request->ip().date('Ymd_His').Str::random(20);
        //$t=hash('sha256', $t);
        $t=$this->encryptPassword($t);

        switch ($this->tokenFieldSource){
            case self::OTP_TOKEN_SOURCE_COOKIE:
                Cookie::queue($this->tokenFieldName,$t,$this->verificationLifeTime);
                break;
        }

        return $t;
    }

    /**
     * @param $userToken
     * @return false|OTPassword
     */
    private function findOTPasswordModelFromUserToken($userToken){
        //check userToken from cookie or request is correct or not
        //check its part (date, contract,...)
        //find otpModel and its user
        /**
         * @var OTPassword $otpModel
         */
        $otpModel=$this->getOTPModelRowsByUserToken($userToken)->first();
        if($otpModel==null){
            return false;
        }

        //return otp-model row

        return $otpModel;

    }

    protected function findUserContactFromRequest(Request $request){
        $uc = $request->all([$this->userContact]);
        return $uc[$this->userContact]??'';
    }

    private function reachedMaximumFailed($userContact, $ip){

        //ip
        if(!empty($this->maximumFaildByIP)) {
            $q = $this->getOTPModelRowsQuery()
                ->where([['user_ip', $ip], ['created_at', Carbon::now()], ['status', '!=', self::OTP_STATUS_VERIFIED]]);
            $res = $q->count();

            if ($res >= $this->maximumFaildByIP)
                return true;
        }

        //contact
        if(!empty($this->maximumFaildByContact)) {
            $q = $this->getOTPModelRowsQuery()
                ->where([['user_contact', $userContact], ['created_at', Carbon::now()], ['status', '!=', self::OTP_STATUS_VERIFIED]]);
            $res = $q->count();

            if ($res >= $this->maximumFaildByContact)
                return true;
        }

        return false;
    }

    public static function generateAndSendNewOTP(Request $request, $user=null){

        $manager=new OTPManager();

        //$user->{$manager->userToken}
        $userToken=$manager->findUserToken($request);
        //generate new userToken in any case
        $userToken=$manager->generateAndStoreNewUserToken($request);

        $ip=$request->ip();

        //todo must be better in choosing from user or request
        $userContact=$user->{$manager->userContact}??'';
        if(empty($userContact))
            $userContact=$manager->findUserContactFromRequest($request);

        if(empty($userContact)){
            //todo message
            return false;
        }

        //check last otp try
        if($manager->isDuplicateRequest($userToken, $userContact)!==false){

            //todo message

            return false;
        }

        //check maximum failed in one day
        if($manager->reachedMaximumFailed($userContact, $ip)){
            //todo message

            return false;
        }


        //generate new otp
        $password=$manager->generateNewPassword($manager->passwordLength,$manager->onlyDigitPassword,$manager->shouldEncodePassword);//code for sms or email

        //save new otp-model in otp table
        $modelOTP=$manager->saveNewOTP($userToken, $userContact, $password, $ip, $user);

        //save userToken in user->otptoken
        $manager->saveUserTokenInUser($user, $userToken);

        //send otp message
        $sent=$manager->otpMessage->sendMessage($userContact,$password);

        //todo if sent successfully then change otp-model status to wait else to error
        if(!empty($sent)){
            $modelOTP->status=self::OTP_STATUS_WAIT;
        }else{
            $modelOTP->status=self::OTP_STATUS_ERROR;
        }
        $modelOTP->save();

        //return otp row data
        return $modelOTP;

    }

    private function saveNewOTP($userToken, $userContact, $password, $ip, $user=null){

        $data=[
            'user_id'=>$user->id??null,
            'user_identify'=>['id'],
            'user_contact'=>$userContact,
            'user_token'=>$userToken,
            'user_ip'=>$ip,
            'password'=>$password,
            'status'=>self::OTP_STATUS_CREATED,
        ];
        /**
         * @var Model $model
         */
        $model=app()->make($this->otpModelClass);
        $model->fill($data);

        $result=$model->save();

        return $model;
    }

    private function getOTPModelRowsQuery():Builder{
        $q=$this->otpModelClass::with('user');
        return $q;
    }

    private function getOTPModelRowsByUserToken($userToken):Builder{
        $q=$this->getOTPModelRowsQuery()->where('user_token',$userToken);
        return $q;
    }

    private function isDuplicateRequest($userToken, $userContact):bool{

        //check by user-token
        //todo is not useful bcs userToken is unique
        $last=$this->getOTPModelRowsByUserToken($userToken)
            ->latest('id')->first();
        if($last!=null){
            if(!$this->hasPassedDelay($last->created_at)){
                return true;
            }
            if(!$this->hasPassedIP($last->ip, $last->created_at)){
                return true;
            }
        }

        //check by user-contact
        $last=$this->otpModelClass::where('user_contact',$userContact)->latest('id')->first();
        if($last!=null){
            if(!$this->hasPassedDelay($last->created_at)){
                return true;
            }
            if(!$this->hasPassedIP($last->ip, $last->created_at)){
                return true;
            }
        }


        return false;
    }

    private function hasPassedDelay($lastDate):bool{
        //hasPassedDelay
        $lastDate=Carbon::parse($lastDate);
        $diff=Carbon::now()->diffInSeconds($lastDate);

        if($diff<$this->minimumDelayPerRequest){
            return false;
        }

        return true;
    }

    private function hasPassedIP($lastIP, $lastDate):bool{
        if(!$this->shouldCheckIP)
            return true;

        $curIP=\request()->ip();
        if($lastIP==$curIP){
            return $this->hasPassedDelay($lastDate);
        }

        return true;
    }

    protected function generateNewPassword($length, $onlyDigit=true, $encrypt=false):string{

        $permitted_digits = '123456789';
        $permitted_chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $input=$onlyDigit?$permitted_digits:$permitted_chars;
        $input_length = strlen($input);
        $random_string = '';
        for($i = 0; $i < $length; $i++) {
            $random_character = $input[random_int(0, $input_length - 1)];
            $random_string .= $random_character;
        }
        $password= $random_string;

        if($encrypt)
            $password=$this->encryptPassword($password);

        return $password;

    }

    public static function getCurrentVerifiedUser(Request $request){
        //get user from request if verified
        $manager=new OTPManager();
        $modelOTP=$manager->getVerifiedOTPModelFromRequest($request);
        if($modelOTP!==false){
            return $modelOTP->user??null;
        }

        return null;
    }

    private function checkWrongTryLimitation(OTPassword $otpModel){
        $otpModel->try=$otpModel->try??0+1;
        if(empty($this->maximumTryToAnswer))
            return;
        if($otpModel->try>=$this->maximumTryToAnswer){
            $otpModel->status=self::OTP_STATUS_EXPIRED;
            $otpModel->save();
        }
    }

    public static function checkUserOTPAndVerification(Request $request, $user_answer){

        $manager=new OTPManager();

        //find userToken and its otpassword-model
        $otpModel=$manager->findOTPasswordModelFromRequest($request);
        if(empty($otpModel))
            return false;

        if(!$otpModel->isReady()){
            //maybe expired or used before
            return false;
        }

        //check user password is correct or not
        if($manager->checkPassword($otpModel,$user_answer)!==true){

            //count wrong answer
            $manager->checkWrongTryLimitation($otpModel);

            return false;
        }

        //if otp was correct remove previous verified rows (single-mode or duplicate-mode)
        if($manager->singleDevice){
            //todo must check (user_contact OR user_id) each one
            $res=$manager->getOTPModelRowsQuery()->where([['user_contact',$otpModel->user_contact],['status',self::OTP_STATUS_VERIFIED]])
                ->update(['status'=>self::OTP_STATUS_EXPIRED]);
        }


        //set user verified
        $otpModel->status=self::OTP_STATUS_VERIFIED;
        $otpModel->verified_at=Carbon::now();
        $otpModel->save();

        $manager->doLoggedInUser($otpModel);

        return $otpModel;
    }

    private function encryptPassword($password){
        return Crypt::encryptString($password);
        //return hash('sha256',$password);
    }

    private function checkPassword(OTPassword $OTPModel, $password){

        if($this->shouldEncodePassword){
            return $this->encryptPassword($password)==$OTPModel->password;
        }

        return $OTPModel->password==$password;

    }

}
