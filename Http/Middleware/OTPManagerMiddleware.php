<?php


namespace App\Http\Middleware;

use Closure;
use HamidMp\OTPManager\OTPManager;

class OTPManagerMiddleware
{

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  boolean $hasVerified
     * @return mixed
     */
    public function handle($request, Closure $next, $hasVerified=true)
    {
        if($hasVerified) {
            if(OTPManager::isVerified($request)!==true){
                return $this->failed($request);
            }
        }else{
            if(OTPManager::findOTPasswordModelFromRequest($request)===false){
                return $this->failed($request);
            }
        }

        return $next($request);
    }

    /**
     * Get the path the user should be redirected to when they are not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    protected function failed($request)
    {
        if (! $request->expectsJson()) {
            return route('login');
        }

        return abort(403);
    }

}
