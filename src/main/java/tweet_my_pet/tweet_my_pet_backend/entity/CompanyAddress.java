package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

@Getter
@Setter
@Entity
@Table(name = "company_address", schema = "tweet_my_pet")
public class CompanyAddress {

    @Id
    @Column(name = "company_address_id", nullable = false)
    private Long companyAddressId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "company_id", nullable = false)
    private Company companyId;

    @Column(name = "company_address_city", nullable = false, length = 45)
    private String companyAddressCity;

    @Column(name = "company_address_district", nullable = false, length = 45)
    private String companyAddressDistrict;

    @Column(name = "company_address_town", nullable = false, length = 45)
    private String companyAddressTown;

    @Column(name = "company_street_address", nullable = false, length = 45)
    private String companyStreetAddress;

    @ColumnDefault("'X'")
    @Column(name = "company_address_detail", length = 45)
    private String companyAddressDetail;

}