<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\ScanUrlRequest;
use Illuminate\Support\Facades\Http;

class ScanUrlController extends Controller
{
    public function scan(ScanUrlRequest $request)
    {
        $response = Http::post(config('services.remote_server.url_scanning_url'), [
            'url' => $request->get('url'),
        ]);

        return response()->json([
            'status' => true,
            'data' => $response->json(),
        ]);
    }
}
