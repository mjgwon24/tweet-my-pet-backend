package tweet_my_pet.tweet_my_pet_backend.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * 글로벌 예외처리 핸들러
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationExceptions(MethodArgumentNotValidException exception) {
        for (FieldError error : exception.getBindingResult().getFieldErrors()) {
            // 비밀번호 유효성 검증 실패의 경우
            if ("password".equals(error.getField())) {
                return new ResponseEntity<>("비밀번호는 문자, 숫자, 특수문자를 포함한 8자 이상이어야 합니다.", HttpStatus.BAD_REQUEST);
            }
        }
        return new ResponseEntity<>("유효성 검증 실패", HttpStatus.BAD_REQUEST);
    }
}
