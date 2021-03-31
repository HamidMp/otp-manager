<?php

use App\Models\User;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddTokenToUser extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        $user=app()->make(config('otpmanager.user_model',User::class));
        $tableName=$user->getTable();
        Schema::table($tableName, function (Blueprint $table) {
            if(!Schema::hasColumn($table->getTable(),config('otpmanager.user_contact','mobile')))
                $table->string(config('otpmanager.user_contact','mobile'),14)->nullable();
            if(!Schema::hasColumn($table->getTable(),config('otpmanager.user_token','otp_token')))
                $table->text(config('otpmanager.user_token','otp_token'))->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('otpassword');
    }
}
