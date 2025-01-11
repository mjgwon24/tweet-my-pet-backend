package tweet_my_pet.tweet_my_pet_backend.exception;

public class AuthExpireException extends AuthException {
    public AuthExpireException(String message) {
        super(message);
    }

    public AuthExpireException(String message, Throwable cause) {
        super(message, cause);
    }
}