<?php


namespace HamidMp\OTPManager\Models;


use HamidMp\OTPManager\OTPManager;
use Illuminate\Database\Eloquent\Model;

class OTPassword extends Model
{
    protected $table='otpassword';

    protected $fillable=[
        'user_id',
        'user_identify',
        'user_contact',
        'user_token',
        'user_ip',
        'password',
        'status',
    ];

    protected $casts=[
        'user_identify'=>'array',
        'verified_at'=>'timestamp',
    ];

    public function user()
    {
        return $this->belongsTo(config('otpmanager.userModel','App\Models\User'));
    }

    final public function hasVerified(){
        return $this->status=== OTPManager::OTP_STATUS_VERIFIED;
    }
    final public function isReady(){
        return in_array($this->status, [
            OTPManager::OTP_STATUS_CREATED,
            OTPManager::OTP_STATUS_WAIT,
        ]);
    }
    final public function hasBroken(){
        return in_array($this->status, [
            OTPManager::OTP_STATUS_ERROR,
            OTPManager::OTP_STATUS_EXPIRED,
        ]);
    }

}
