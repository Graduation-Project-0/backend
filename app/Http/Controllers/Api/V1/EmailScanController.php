<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\EmailRequest;
use App\Support\Services\HistoryService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class EmailScanController extends Controller
{
    public function standardScanEmail(EmailRequest $request)
    {
        $response = Http::attach(
            'file',
            file_get_contents($request->file('email')),
            $request->file('email')->getClientOriginalName()
        )->post(config('services.remote_server.email_scanning_url_standard'));

        HistoryService::createHistory($request->user(), 'email', null, $response->json());

        return response()->json([
            'status' => true,
            'data' => $response->json(),
        ]);
    }
}
