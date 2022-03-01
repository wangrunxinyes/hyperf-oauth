<?php

namespace Richard\HyperfPassport\Controller;

use Hyperf\Di\Resolver\ObjectResolver;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Richard\HyperfPassport\TokenRepository;
use Lcobucci\JWT\Parser as JwtParser;
use League\OAuth2\Server\AuthorizationServer;
use Nyholm\Psr7\Response as Psr7Response;
use Psr\Http\Message\ServerRequestInterface;
use Whyperf\Whyperf;

class AccessTokenController {

    use HandlesOAuthErrors;

    /**
     * The authorization server.
     *
     * @var \League\OAuth2\Server\AuthorizationServer
     */
    protected $server;

    /**
     * The token repository instance.
     *
     * @var \Richard\HyperfPassport\TokenRepository
     */
    protected $tokens;

    /**
     * The JWT parser instance.
     *
     * @var \Lcobucci\JWT\Parser
     *
     * @deprecated This property will be removed in a future Passport version.
     */
    protected $jwt;

    /**
     * Create a new controller instance.
     *
     * @param  \League\OAuth2\Server\AuthorizationServer  $server
     * @param  \Richard\HyperfPassport\TokenRepository  $tokens
     * @return void
     */
    public function __construct(AuthorizationServer $server,
            TokenRepository $tokens) {
        /**
         * @var Configuration $configuration
         */
        $configuration = Whyperf::getContainer()->get(Configuration::class);
        $this->jwt = $configuration->parser();
        $this->server = $server;
        $this->tokens = $tokens;
    }

    /**
     * Authorize a client to access the user's account.
     *
     * @param  \Psr\Http\Message\ServerRequestInterface  $request
     * @return \Hyperf\HttpMessage\Server\Response
     */
    public function issueToken(ServerRequestInterface $request) {
        return $this->withErrorHandling(function () use ($request) {
                    return $this->convertResponse(
                                    $this->server->respondToAccessTokenRequest($request, new Psr7Response)
                    );
                });
    }

}
