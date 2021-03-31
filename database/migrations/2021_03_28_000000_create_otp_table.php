<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateOtpTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('otpassword', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->nullable();
            $table->json('user_identify');
            $table->string('user_contact');
            $table->string('user_token',400)->unique();
            $table->string('user_ip');
            $table->timestamp('verified_at')->nullable();
            $table->string('password');
            $table->tinyInteger('try')->default(0);
            $table->tinyInteger('status')->default(0);
            $table->timestamps();
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
