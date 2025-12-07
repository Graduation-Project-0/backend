<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\EmailRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class EmailScanController extends Controller
{
    public function standardScanEmail(EmailRequest $request)
    {
        $response = Http::attach(
            'email',
            file_get_contents($request->file('email')),
            $request->file('email')->getClientOriginalName()
        )->post(config('services.remote_server.email_scanning_url_standard'));

        return response()->json([
            'status' => true,
            'data' => $response->json(),
        ]);
    }
}
