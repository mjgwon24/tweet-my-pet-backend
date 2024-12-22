package tweet_my_pet.tweet_my_pet_backend.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto;
import tweet_my_pet.tweet_my_pet_backend.dto.StoreDto.CreateStoreRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.room.RoomDto;
import tweet_my_pet.tweet_my_pet_backend.dto.room.RoomDto.CreateRoomRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.store.StoreFeatureDto.CreateStoreFeatureRequest;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.PetSizeType;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Room;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;
import tweet_my_pet.tweet_my_pet_backend.entity.store.StoreFeature;
import tweet_my_pet.tweet_my_pet_backend.repository.RoomRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.StoreRepository;
import org.locationtech.jts.geom.Point;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
class StoreServiceTest {
    @Autowired
    private StoreService storeService;
    @Autowired
    private StoreRepository storeRepository;
    @Autowired
    private RoomRepository roomRepository;

    @Test
    @DisplayName("매장 추가 기능 테스트")
    void createStore() {
        // given: CreateStoreRequest 생성
        CreateStoreFeatureRequest featureRequest = CreateStoreFeatureRequest.builder()
                .acceptPetSizes(List.of(PetSizeType.small, PetSizeType.medium))
                .isParking(true)
                .isDogPark(true)
                .isDogSwimmingPool(true)
                .isInternet(true)
                .isBarbecue(true)
                .build();

        CreateRoomRequest roomRequest1 = CreateRoomRequest.builder()
                .roomType("single")
                .pricePerNight(10000)
                .totalRoomCount(10)
                .build();

        CreateRoomRequest roomRequest2 = CreateRoomRequest.builder()
                .roomType("double")
                .pricePerNight(20000)
                .totalRoomCount(5)
                .build();

        CreateStoreRequest storeRequest = CreateStoreRequest.builder()
                .storeName("store1")
                .storeTel("010-1234-5678")
                .storeLocation("서울시 강남구")
                .latitude(37.1234)
                .longitude(127.1234)
                .petGuide("애견 동반 가능")
                .useGuide("예약 필수")
                .feature(featureRequest)
                .rooms(List.of(roomRequest1, roomRequest2))
                .build();

        // when: Store 저장
        StoreDto.FetchStoreResponse response = storeService.createStore(storeRequest);

        // then: Store 저장 확인
        assertNotNull(response);
        assertEquals("store1", response.storeName());
        assertEquals("010-1234-5678", response.storeTel());

        // 저장된 StoreFeature 확인
        Store store = storeRepository.findById(response.id()).orElseThrow();
        StoreFeature storeFeature = store.getStoreFeature();
        assertNotNull(storeFeature);
        assertEquals(List.of(PetSizeType.small, PetSizeType.medium), storeFeature.getAcceptPetSizes());
        assertTrue(storeFeature.getIsParking());
        assertTrue(storeFeature.getIsDogPark());
        assertTrue(storeFeature.getIsDogSwimmingPool());

        // 저장된 Room 확인
        List<Room> rooms = roomRepository.findAllByStoreId(store.getId());
        assertEquals(2, rooms.size());

        Room room1 = rooms.get(0);
        Room room2 = rooms.get(1);

        assertEquals("single", room1.getRoomType());
        assertEquals(10000, room1.getPricePerNight());
        assertEquals(10, room1.getTotalRoomCount());

        assertEquals("double", room2.getRoomType());
        assertEquals(20000, room2.getPricePerNight());
        assertEquals(5, room2.getTotalRoomCount());
    }

}