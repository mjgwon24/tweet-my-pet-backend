package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.dto.SignupRequestDto;
import tweet_my_pet.tweet_my_pet_backend.entity.Users;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;

/**
 * 사용자 서비스
 * @since 24.10.26
 * @latest 24.10.26
 * @author 권민지
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UsersRepository usersRepository;

    /**
     * 회원가입
     * @param signupRequestDto
     */
    @Transactional
    public Users signUp(SignupRequestDto signupRequestDto) {
        Users user = Users.builder()
                .loginId(signupRequestDto.getLoginId())
                .password(signupRequestDto.getPassword())
                .name(signupRequestDto.getName())
                .phoneNumber(signupRequestDto.getPhoneNumber())
                .build();
        return usersRepository.save(user);
    }
}
