<?php


namespace HamidMp\OTPManager;


interface OTPMessageInterface
{

    public function sendMessage($contact, $OTPassword, $content=''):bool;

}
