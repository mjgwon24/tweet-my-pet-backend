package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Room;

import java.util.List;

@Repository
public interface RoomRepository extends JpaRepository<Room, Long> {
    // StoreId로 Room 모두 조회
    List<Room> findAllByStoreId(Long storeId);
}
